# LDAP / Active Directory Authentication

Preparing a Windows Active Directory domain for Wazuh dashboard/indexer LDAP authentication, and troubleshooting the most common integration failure: TLS hostname verification.

Official integration guide: [Active Directory LDAP authentication](https://documentation.wazuh.com/current/user-manual/user-administration/single-sign-on/administrator/active-directory-ldap.html)

## Table of Contents

- [Prepare the AD side](#prepare-the-ad-side)
  - [1. Create Organizational Units](#1-create-organizational-units)
  - [2. Create a privileged bind user](#2-create-a-privileged-bind-user)
  - [3. Create a group for Wazuh access](#3-create-a-group-for-wazuh-access)
  - [4. Add the user to the group](#4-add-the-user-to-the-group)
  - [5. Verify](#5-verify)
- [Values to collect for the Wazuh configuration](#values-to-collect-for-the-wazuh-configuration)
- [Troubleshooting](#troubleshooting)
  - [Hostname verification failures (LDAPS)](#hostname-verification-failures-ldaps)
  - [Testing binds with ldapsearch](#testing-binds-with-ldapsearch)
- [Related guides](#related-guides)

## Prepare the AD side

All commands run in PowerShell on a domain controller (adjust the DNs to your domain: the examples use `example.local`).

### 1. Create Organizational Units

One OU for users and one for groups:

```powershell
New-ADOrganizationalUnit -Name "people" -Path "DC=example,DC=local"
New-ADOrganizationalUnit -Name "Groups" -Path "DC=example,DC=local"
```

### 2. Create a privileged bind user

The service account Wazuh uses to bind and search the directory:

```powershell
New-ADUser -Name "WazuhUser" `
  -GivenName "Wazuh" `
  -Surname "User" `
  -SamAccountName "WazuhUser" `
  -UserPrincipalName "WazuhUser@example.local" `
  -Path "OU=people,DC=example,DC=local" `
  -AccountPassword (ConvertTo-SecureString "<BIND_PASSWORD>" -AsPlainText -Force) `
  -Enabled $true
```

### 3. Create a group for Wazuh access

```powershell
New-ADGroup -Name "Wazuh_Admins" `
  -GroupScope Global `
  -Path "OU=Groups,DC=example,DC=local" `
  -Description "Group for users with access to Wazuh"
```

### 4. Add the user to the group

```powershell
Add-ADGroupMember -Identity "Wazuh_Admins" -Members "WazuhUser"
```

### 5. Verify

```powershell
Get-ADUser -Filter {SamAccountName -eq "WazuhUser"} | Select-Object DistinguishedName
Get-ADGroup -Filter {Name -eq "Wazuh_Admins"} | Select-Object DistinguishedName
```

## Values to collect for the Wazuh configuration

For the OpenSearch security `config.yml` (authc/authz LDAP sections) you need:

| Item | Example |
|---|---|
| User base DN | `OU=people,DC=example,DC=local` |
| Group base DN | `OU=Groups,DC=example,DC=local` |
| Bind user DN | `CN=WazuhUser,OU=people,DC=example,DC=local` |
| Access group DN | `CN=Wazuh_Admins,OU=Groups,DC=example,DC=local` |
| LDAP server FQDN | `dc1.example.local` |

To find the domain controller's real FQDN (the DNS host name plus the domain):

```powershell
([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME)).HostName
# or the parts separately:
wmic computersystem get DNSHostName
wmic computersystem get Domain
```

## Troubleshooting

### Hostname verification failures (LDAPS)

The most common integration failure with `ldaps://` (port 636): the security plugin rejects the connection because the hostname in the configuration does not match the certificate.

1. **Use the FQDN, not the IP.** The `hosts` entry must match the certificate's CN/SAN:

   ```yaml
   hosts:
     - dc1.example.local:636
   ```

2. **Check what name the certificate actually carries:**

   ```bash
   openssl s_client -connect <LDAP_SERVER>:636 -showcerts
   ```

   Look at the Common Name (CN) and Subject Alternative Names, and use that value in the configuration. The Wazuh/indexer host must also be able to resolve that name (DNS or `/etc/hosts`).

3. **Temporary test-only workaround:** disable hostname verification in the LDAP section of `config.yml`:

   ```yaml
   verify_hostnames: false
   ```

   > Do not leave this in production; it defeats the point of TLS.

After changing the configuration, apply it with `securityadmin.sh`, restart the affected services, and test a directory login.

### Testing binds with ldapsearch

Validate credentials and DNs from the Wazuh server before touching `config.yml`:

```bash
# Plain LDAP (389), UPN-style bind
ldapsearch -x -H ldap://<LDAP_SERVER>:389 \
  -D "WazuhUser@example.local" -W \
  -b "OU=people,DC=example,DC=local"

# DN-style bind, searching for a specific account
ldapsearch -H ldap://<LDAP_SERVER>:389 \
  -D "CN=WazuhUser,OU=people,DC=example,DC=local" \
  -w '<BIND_PASSWORD>' \
  -b "DC=example,DC=local" \
  "(sAMAccountName=<USER>)"

# LDAPS with certificate checks disabled and client debug output (diagnosis only)
LDAPTLS_REQCERT=never ldapsearch -d 1 -H ldaps://<LDAP_SERVER>:636 \
  -D "CN=WazuhUser,OU=people,DC=example,DC=local" \
  -w '<BIND_PASSWORD>' \
  -b "DC=example,DC=local" \
  "(sAMAccountName=<USER>)"
```

If `ldapsearch` fails, fix the bind DN / password / network reachability first: the Wazuh configuration cannot work until these succeed.

## Related guides

- [passwords-recovery.md](passwords-recovery.md) - internal users remain available as a fallback when external authentication breaks
- TLS certificate diagnostics (the `openssl s_client` flow) are covered in the certificates section of this knowledge base
