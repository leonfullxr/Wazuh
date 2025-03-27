# Send alerts from Wazuh to Microsoft Teams via wazuh-integratord
Create the files in /var/ossec/integrations/

```bash
chmod 750 /var/ossec/integrations/custom-teams*
chown root:wazuh /var/ossec/integrations/custom-teams*
```

Edit Wazuh Configuration: Open the Wazuh configuration file located at /var/ossec/etc/ossec.conf and add the following integration block:

```xml
<integration> 
<name>custom-teams</name> 
<hook_url>https://yourdomain.webhook.office.com/webhookb2/f86972bc-f2a5-41f5-bf1ewqa@4354534534-8465-f3b9780f866e/IncomingWebhook/fdsf534538ec8e0e/71785f5f-83a13243220a-c507a817742a/V43243242Zo856545341 </hook_url> <! - Replace with your webhook URL → 
<level>12</level> <! - Minimum alert level to trigger the integration → 
<alert_format>json</alert_format> 
</integration>
```

Finally, restart the Wazuh manager to apply the changes:

```bash
systemctl restart wazuh-manager
```
