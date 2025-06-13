# Introduction
Splunk integration with Wazuh via integrator to send wazuh alerts for splunk SOAR

Be aware that this method could present some delays in uploading the data depending on how many events per second you need to send.

# Configuration
Here’s a sample of how to configure your Wazuh managers:

```xml
<!-- Integration with Splunk -->
<integration>
  <name>custom-splunk</name>
  <hook_url>https://<WEBHOOK></hook_url>
  <api_key>-KEY-</api_key>
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>
```

# Example
```bash
[root@wazuh-manager-master-0 /]# cd /var/ossec/integrations/
[root@wazuh-manager-master-0 integrations]# ls
maltiverse  maltiverse.py  pagerduty  pagerduty.py  shuffle  shuffle.py  slack  slack.py  virustotal  virustotal.py
[root@wazuh-manager-master-0 integrations]# touch custom-splunk.py
[root@wazuh-manager-master-0 integrations]# vi custom-splunk.py
[root@wazuh-manager-master-0 integrations]# vi /var/ossec/etc/ossec.conf
[root@wazuh-manager-master-0 integrations]# ls
custom-splunk.py  maltiverse.py  pagerduty.py  shuffle.py  slack.py    virustotal.py
maltiverse        pagerduty      shuffle       slack       virustotal
[root@wazuh-manager-master-0 integrations]# cp slack custom-splunk
[root@wazuh-manager-master-0 integrations]# chown root:wazuh custom*
[root@wazuh-manager-master-0 integrations]# chmod 750 custom-splunk.py
[root@wazuh-manager-master-0 integrations]# ll
total 84
-rwxr-x---. 1 root wazuh  1045 Jan 16 22:46 custom-splunk
-rwxr-x---. 1 root wazuh  1981 Jan 16 22:45 custom-splunk.py
-rwxr-x---. 1 root wazuh  1045 Dec 11 16:40 maltiverse
-rwxr-x---. 1 root wazuh 17358 Dec 11 16:40 maltiverse.py
-rwxr-x---. 1 root wazuh  1045 Dec 11 16:40 pagerduty
-rwxr-x---. 1 root wazuh  7078 Dec 11 16:40 pagerduty.py
-rwxr-x---. 1 root wazuh  1045 Dec 11 16:40 shuffle
-rwxr-x---. 1 root wazuh  7688 Dec 11 16:40 shuffle.py
-rwxr-x---. 1 root wazuh  1045 Dec 11 16:40 slack
-rwxr-x---. 1 root wazuh  7277 Dec 11 16:40 slack.py
-rwxr-x---. 1 root wazuh  1045 Dec 11 16:40 virustotal
-rwxr-x---. 1 root wazuh  9785 Dec 11 16:40 virustotal.py
[root@wazuh-manager-master-0 integrations]# service wazuh-manager restart
```
