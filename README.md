# Disabled SPN Kerberoasting

This is a PoC of a vulnerability that can bypass exception handling in Microsoft Kerberos that I presented at the DefCamp2025 Conference.
Microsoft has written code to block Kerberos access to disabled accounts, but AS-REQ, which shares the same structure as TGS-REQ, can bypass this exception handling, resulting in access to service tickets for disabled accounts.
For detailed analysis, please refer to the link below.
