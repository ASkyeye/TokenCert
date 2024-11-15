# TokenCert
## Overview

TokenCert is a C# tool that will create a network token (*LogonType 9*) using a provided certificate via **PKINIT**. 
This way, we can have a make-token functionality using certificates instead of passwords. The tool was created after reading the excellent post "Understanding and evading Microsoft Defender for Identity PKINIT detection".

Instead of creating a new process (as the original POC does), we are instead invoking **LogonUserA** and **ImpersonateLoggedOnUser** to authenticate and impersonate the specified certificate user. This way, the TGT request for the provided account is performed from the OS avoiding any abnormal behaviors like irregular AS-REQ messages and / or [Kerberos Traffic from Unusual Process](https://www.elastic.co/guide/en/security/current/kerberos-traffic-from-unusual-process.html).


## Windows Events
Once the tool is executed we will get the following events:

* **Client - Event 4624 - An account was successfully logged on**

![client](https://github.com/user-attachments/assets/e84c0bc2-6932-4d3f-a46e-b7f55535eff1)

  * LogonType 9 (New Credentials)  - Clones current LSA session for local access, but uses new credentials when connecting to network resources.
    * Network account Name is actually ```@@Bw8Ep8pKYTYvcuN2U31Y99I1fI2G```
    * Effectively is the marshalled credential from the invocation of CredMarshalCredential. It can be reversed using CredUnmarshalCredential. [This](https://x.com/awakecoding/status/1627708142287978496) twitter thread was actually quite interesting



* **Domain Controller - Event 4768 - A Kerberos authentication ticket (TGT) was requested**

![dc](https://github.com/user-attachments/assets/55bb2038-0363-4879-b5d9-e4af06664e02)

  * Account Information contains the requesting username (Account Name: alice) and Client Address field the IP of the host that the request originated from
  * Ticket Options is 0x40810010 translating to Forwardable + Renewable + Canonicalize + Renewable Ok. More details [here](https://trustedsec.com/blog/the-art-of-bypassing-kerberoast-detections-with-orpheus)
  * Pre-Authentication Type 16. Typical to see in PKINIT authentication scenarios as it is the PA-PK-AS-REQ. More details for Pre-Authentication Types [here](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768#table-5-kerberos-pre-authentication-types)


## Usage

```
tokencert.exe -Cert <base64> -Domain <domain> [-Password <PasswordOfCertificate>]
```

## Acknowledgments

This tool is inspired by the research of Synacktiv in their article [Understanding and evading Microsoft Defender for Identity PKINIT detection](https://www.synacktiv.com/publications/understanding-and-evading-microsoft-defender-for-identity-pkinit-detection) and their tool [Invoke-RunAsWithCert](https://github.com/synacktiv/Invoke-RunAsWithCert)

Lefteris (Lefty) Panos @ 2024 - LRQA Red Team
