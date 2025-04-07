# EPS Calculation Script for Wazuh-Manager
# Description
To perform the EPS calculation, I attach the following zip file containing the epscount.zip script, which must be executed as described below:

- Download the script to the server where Wazuh-Manager is installed and move it to the directory:
    

`/var/ossec/logs/archives mv epschat_log.sh /var/ossec/logs/archives`

- Edit the `ossec.conf` file on the server where Wazuh-Manager is installed by modifying the contents of the `<logall>` tag to ‘yes’:
    

`nano /var/ossec/etc/ossec. conf <logall>yes</logall>`

- Restart Wazuh-Manager to apply the changes:
    

`systemctl restart wazuh-manager`

- Place it in the `archives` folder, give it permission to run the script:
    

`cd /var/ossec/logs/archives/ chmod +x epschat_log. sh`

- Run the script by suffixing it with the name of the file containing the logs, in this case `archives.log`_**:**_
    

`./epschat_log.sh.sh.sh archives.log`

- This will provide real-time EPS as events coming into Wazuh are logged in `archives. log`:
    
- Remember to disable `<logall>`, restoring its value to the original `no` to avoid overloading the memory of the server on which Wazuh-Manager is installed:
    

`nano /var/ossec/etc/ossec.conf <logall>no</logall>`.