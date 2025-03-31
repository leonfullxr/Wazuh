# LDAPS Windows Server
This is a general guide for creating a windows LDAPS server for integrating it into wazuh
### 1. Create Organizational Units

To create an OU for users (e.g., "people") and one for groups (e.g., "Groups"), run the following commands:

```powershell
# Create an OU for People
New-ADOrganizationalUnit -Name "people" -Path "DC=ad,DC=gpfs,DC=net"

# Create an OU for Groups
New-ADOrganizationalUnit -Name "Groups" -Path "DC=ad,DC=gpfs,DC=net"
```

### 2. Create a Privileged Bind User

For example, to create a user called "Wazuh User" in the People OU:

```powershell
New-ADUser -Name "WazuhUser" `
  -GivenName "Wazuh" `
  -Surname "User" `
  -SamAccountName "WazuhUser" `
  -UserPrincipalName "WazuhUser@wazuh.local" `
  -Path "OU=USERS,OU=WAZUH,DC=wazuh,DC=local" `
  -AccountPassword (ConvertTo-SecureString "password123?" -AsPlainText -Force) `
  -Enabled $true
```

### 3. Create a Group for Wazuh Access

For example, to create a group called "Wazuh_Admins" in the Groups OU:

```powershell
New-ADGroup -Name "Wazuh_Admins" `
  -GroupScope Global `
  -Path "OU=WAZUH,DC=wazuh,DC=local" `
  -Description "Group for users with access to Wazuh"
```

### 4. Add the User to the Group

Once the user and group are created, add the user to the group:

```powershell
Add-ADGroupMember -Identity "Wazuh_Admins" -Members "WazuhUser"
```

### 5. Verify Your Configuration

You can verify that the user and group were created successfully by running:

```powershell
Get-ADUser -Filter {SamAccountName -eq "WazuhUser"} | Select-Object DistinguishedName
Get-ADGroup -Filter {Name -eq "Wazuh_Admins"} | Select-Object DistinguishedName
```

### Additional Information

- **FQDN of the LDAP Server:**  
    From your output, your DNSHostName is `vagrant` and your Domain is `ad.gpfs.net`. This means your full domain name for the AD server is likely something like `vagrant.ad.gpfs.net`.
    
- **Configuration Summary:**  
    For LDAP integration with Wazuh, you'll need to collect:
    
    - **User OU DN:** e.g., `OU=people,DC=ad,DC=gpfs,DC=net`
    - **Group OU DN:** e.g., `OU=Groups,DC=ad,DC=gpfs,DC=net`
    - **Bind User DN:** e.g., `CN=Wazuh User,OU=people,DC=ad,DC=gpfs,DC=net`
    - **Group for Wazuh Access:** e.g., `CN=Wazuh_Admins,OU=Groups,DC=ad,DC=gpfs,DC=net`
    - **LDAP Server FQDN:** e.g., `vagrant.ad.gpfs.net`

You can then update your Wazuh configuration files with these values.

---

These commands and steps should allow you to create the necessary users, groups, and OUs directly from the PowerShell command line in your AD environment.

Let me know if you need any further assistance!

# Troubleshooting
Hi,

The error message indicates that when connecting to your LDAP server on port 636 (LDAPS), the SSL handshake fails because the IP address (192.168.56.107) doesn’t match the hostname listed in the server’s certificate. This is causing the LDAP authentication to fail for your user (leon).

### How to Resolve This Issue

1. **Use the Correct FQDN:**  
    Instead of specifying the LDAP server’s IP address in your configuration, use its Fully Qualified Domain Name (FQDN) that matches the certificate. For example, if your LDAP server’s certificate is issued for `ldap.example.com`, update your configuration to use:
    
    ```yaml
    hosts:
      - ldap.example.com:636
    ```
    
    This ensures that during the SSL handshake, the hostname in the certificate matches the one used by the client.
    
2. **Disable Hostname Verification (Not Recommended for Production):**  
    If using the correct FQDN is not an option in your test environment, you can disable hostname verification. In your configuration file, you can set:
    
    ```yaml
    verify_hostnames: false
    ```
    
    However, keep in mind that disabling hostname verification can reduce security and should only be done temporarily for testing.
    
3. **Review Your Certificate:**  
    Verify the details of your LDAP server certificate to confirm the correct hostname. You can do this by connecting with an SSL tool or via a browser:
    
    ```bash
    openssl s_client -connect 192.168.56.107:636 -showcerts
    ```
    
    Look for the Common Name (CN) in the certificate, and then use that value in your configuration.
    

### Next Steps

- **Update the LDAP Configuration:**  
    Modify your LDAP configuration (in your Wazuh/OpenSearch Security config file) to use the FQDN that matches the certificate.
- **Test the Connection:**  
    After updating the configuration, restart the relevant services and test again with your AD user (leon).

Yes, that's correct. The command

```powershell
([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME)).HostName
```

returned `vagrant.ad.gpfs.net`, which is the fully qualified domain name (FQDN) of your Windows server. This FQDN is what you should use in your LDAP configuration when hostname verification is enabled.

The output from

```cmd
wmic computersystem get DNSHostName
wmic computersystem get Domain
ldapsearch -x -H ldap://192.168.56.107:389 -D "leon@ad.gpfs.net" -W -b "OU=people,DC=ad,DC=gpfs,DC=net"
```

shows the separate parts (`vagrant` and `ad.gpfs.net`), but combining them as done by the PowerShell command gives you the full FQDN: `vagrant.ad.gpfs.net`.

`curl -u your_jira_username:your_jira_token -X POST -H "Content-Type: application/json" \`
     `-d '{"fields": {"project": {"key": "YOURPROJECT"}, "summary": "Test Issue from Wazuh Integrator", "description": "Testing integration", "issuetype": {"name": "Task"}}}' \`
     `https://your-jira-domain/rest/api/2/issue`


userldap2

ldap server:
ims.pci
