#!/bin/bash
# install-aio.sh - Unattended Wazuh all-in-one installer (indexer + manager +
# dashboard + filebeat) for any 4.x version, using the official
# wazuh-install.sh assistant.
#
# Usage: sudo ./install-aio.sh <version>
#   e.g.: sudo ./install-aio.sh 4.12   (installs Wazuh 4.12, latest hotfix)
#
# Features:
#   - Validates root, internet connectivity, and the requested version
#   - Detects package manager (apt/yum/zypper) and CPU arch (x86_64/ARM)
#   - Auto-fills config.yml with the host IP for all components
#   - Generates self-signed certificates and random passwords
#   - Optionally resets the indexer 'admin' password (lab use)

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BLUEBRIGHT='\033[1;34m'
YELL='\033[0;33m'
NC='\033[0m'

echo
if [ "$EUID" -ne 0 ]; then echo -e "$RED ERROR: This script must be run as root.$NC"; echo; exit 1
else echo -e "$GREEN INFO: Script runs with root privileges ... OK$NC"
fi
if timeout 0.25 ping -c 1 google.com > /dev/null 2>&1; then echo -e "$GREEN INFO: Internet connection verified ... OK$NC"
else echo -e "$RED ERROR: No Internet connection. Please, check the network settings. Exiting ..."; echo; exit 1
fi

if [ "$#" -ne 1 ]; then echo -e "$RED ERROR: Missing argument.$NC Usage: '$0 version' (${BLUEBRIGHT}e.g.: '$0 4.12'${NC}, to install Wazuh 4.12 -latest hotfix-)"; echo; exit 1
else
  WVer=$1
  if curl -fsSL --connect-timeout 2 https://packages.wazuh.com/${WVer}/config.yml > /dev/null 2>&1; then echo -e "$GREEN INFO: Wazuh version $WVer check ... OK $NC"
  else echo -e "$RED ERROR: Invalid Wazuh version ${WVer}. Exiting ... $NC"; echo; exit 1
  fi
fi

if command -v apt > /dev/null 2>&1; then pckMan=apt
  elif command -v yum > /dev/null 2>&1; then pckMan=yum
  elif command -v zypper > /dev/null 2>&1; then pckMan=zypper
  else
    echo -e "$RED ERROR: Package manager not detected$NC (yum/apt/zypper not found). Exiting ..."
    exit 1
fi

MyIPP=$(hostname -I); MyIP=$(echo ${MyIPP::-1})
if [ "$(uname -m)" == "aarch64" ] || [ "$(uname -m)" == "arm64" ]; then osArch=ARM; else osArch=x86_64; fi
echo -e "${BLUEBRIGHT}\n Data collected:\n $BLUE IP detected: ${YELL}$MyIP \n $BLUE Package manager: ${YELL}$pckMan$BLUE \n  Version: ${YELL}$WVer$BLUE \n  Internet: ${YELL}OK\n $BLUE OS arch:$YELL $osArch $NC\n"
printf "$YELL Continue? [Y/n]: $NC"; read myOp
if [ "$myOp" = "n" ] || [ "$myOp" = "N" ]; then echo " Exiting ..."; exit 0; fi

echo
echo -e "$BLUEBRIGHT Installing useful packages ...$NC"
eval $pckMan install -y curl tar net-tools cifs-utils lsof sudo tcpdump vim jq > /dev/null 2>&1
echo -e "$BLUEBRIGHT Downloading config.yml and installation script ...$NC"
if [ "$WVer" == "4.3" ] || [ "$WVer" == "4.4" ] || [ "$WVer" == "4.5" ]; then curl -sO https://packages.wazuh.com/4.10/config.yml
else curl -sO https://packages.wazuh.com/${WVer}/config.yml
fi
curl -sO https://packages.wazuh.com/${WVer}/wazuh-install.sh

echo -e "$BLUEBRIGHT Changing config.yml file ...$NC"
echo
sed -i "s|   ip: \"<indexer-node-ip>\"|   ip: $MyIP|g" config.yml; sed -i "s|   ip: \"<wazuh-manager-ip>\"|   ip: $MyIP|g" config.yml; sed -i "s|   ip: \"<dashboard-node-ip>\"|   ip: $MyIP|g" config.yml; cat config.yml | grep -v \#
echo

echo -e "$BLUEBRIGHT === Generating self-signed certificates ===$NC"
bash wazuh-install.sh --generate-config-files -i
if [ -f wazuh-install-files.tar ]; then
  echo -e "$GREEN INFO: Certificates and random passwords generated successfully ...$NC"
else
  echo -e "\n$RED ERROR: Something went wrong ... exiting.\n$NC"
  exit 1
fi
echo -e "$BLUE === Certificates DONE ===$NC"; echo

echo -e "$BLUEBRIGHT === Installing Indexer ===$NC"
bash wazuh-install.sh --wazuh-indexer node-1 -i; bash wazuh-install.sh --start-cluster -i; AdmPass=$(tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O | grep -P "\'admin\'" -A1 | tail -1 | cut -c 22-53); echo; echo 'curl -k -u admin:${AdmPass} https://$(echo ${MyIP::-1}):9200 | jq'; curl -k -u admin:${AdmPass} https://${MyIP}:9200 | jq
echo -e "$BLUE === Indexer DONE ===$NC"; echo

if [ $osArch == "ARM" ]; then sed -i 's|libcap2-bin software-properties-common gnupg|libcap2-bin gnupg|g' wazuh-install.sh; fi

echo -e "$BLUEBRIGHT === Installing Server (w/FB) ===$NC"
bash wazuh-install.sh --wazuh-server wazuh-1 -i
echo -e "$BLUE === SERVER DONE ===$NC"; echo

echo -e "$BLUEBRIGHT === Installing Dashboard ===$NC"
bash wazuh-install.sh --wazuh-dashboard dashboard -i
echo -e "$BLUE === DASHBOARD DONE ===$NC"; echo

echo -e "$BLUEBRIGHT === PASSWORDS ===$RED"
tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt | grep '._password: ' -B2
echo -e "$BLUE === PASSWORDS DONE ===$NC"
echo
for s in wazuh-indexer wazuh-manager wazuh-dashboard filebeat; do
  systemctl status --no-pager $s.service | head -4 | grep --color="auto" -i ' Active: ' -A3 -B3; echo
done

echo
printf "$YELL Run 'filebeat test output' check? [Y/n]: $NC"; read myOp
if [ -z "$myOp" ] || [ "$myOp" == 'y' ]; then echo; filebeat test output; fi
echo
echo -e "$YELL ===== ALL DONE =====$NC"
echo

printf "$YELL Set 'admin' password to admin user? [Y/n]: $NC"; read myOp
if [ "$myOp" = "n" ] || [ "$myOp" = "N" ]; then echo -e "\n$BLUEBRIGHT Finished.$NC"; echo; exit 0
else
  capem=/etc/wazuh-indexer/certs/root-ca.pem; adminpem=/etc/wazuh-indexer/certs/admin.pem; adminkey=/etc/wazuh-indexer/certs/admin-key.pem; export JAVA_HOME=/usr/share/wazuh-indexer/jdk; backupdir="/usr/share/wazuh-indexer/backup_$(date +%Y%m%d_%H%M)"; mkdir -p $backupdir
  echo -e "$BLUEBRIGHT INFO: Data collected and backup folder '$backupdir' created ...$NC"
  cd /usr/share/wazuh-indexer; plugins/opensearch-security/tools/securityadmin.sh -backup ${backupdir} -nhnv -cacert ${capem} -cert ${adminpem} -key ${adminkey} -icl -h ${MyIP} > /dev/null 2>&1
  echo -e "$BLUEBRIGHT INFO: Backup pulled from Indexer ...$NC"
  MyNewPass='  hash: "'$(plugins/opensearch-security/tools/hash.sh -p admin | tail -1)'"'; MyOldPass=$(grep ^admin: $backupdir/internal_users.yml -A1 | tail -1)
  replacePass="sed -i 's|"$MyOldPass"|"$MyNewPass"|g' $backupdir/internal_users.yml"
  eval $replacePass > /dev/null 2>&1
  echo -e "$BLUEBRIGHT INFO: New hash for 'admin' replaced ...$NC"
  plugins/opensearch-security/tools/securityadmin.sh -f ${backupdir}/internal_users.yml -nhnv -cacert /etc/wazuh-indexer/certs/root-ca.pem -cert /etc/wazuh-indexer/certs/admin.pem -key /etc/wazuh-indexer/certs/admin-key.pem -icl -h ${MyIP} > /dev/null 2>&1
  echo -e "$BLUEBRIGHT INFO: Pushed new password to Indexer ...$NC"
  echo admin | filebeat keystore add password --force --stdin > /dev/null 2>&1; echo admin | /var/ossec/bin/wazuh-keystore -f indexer -k password > /dev/null 2>&1
  echo -e "$BLUEBRIGHT INFO: Updated Filebeat and Wazuh keystores for 'admin' password ...$NC"
  echo -e "$BLUEBRIGHT INFO: Restarting Filebeat and Wazuh Manager ...$NC"
  systemctl restart filebeat wazuh-manager > /dev/null 2>&1
  echo -e "$BLUEBRIGHT INFO: Checking services ...$NC"
  echo
  for s in wazuh-indexer wazuh-manager filebeat; do
    systemctl status --no-pager $s.service | head -4 | grep --color="auto" -i ' Active: ' -A1 -B2; echo
  done
  echo
  printf "$YELL Test admin password in Indexer and Filebeat? [Y/n]: $NC"; read myOp
  if [ "$myOp" = "n" ] || [ "$myOp" = "N" ]; then echo -e "$BLUEBRIGHT Password changed but no tests were performed.$NC"; exit 0
  else echo -e "$GREEN \n\n $ filebeat test output $NC"; filebeat test output; echo -e "\n\n$GREEN $ curl -sku admin:admin https://${MyIP}:9200 | jq $NC"; curl -sku admin:admin https://${MyIP}:9200 | jq; echo; echo -e "\n$BLUEBRIGHT Remember to clean Browser's cache and cookies -$RED https://${MyIP}$NC"
  fi
fi

echo
echo -e "$GREEN Dashboard runs on '${RED}https://${MyIP}${NC}'"
echo
cd ~/
