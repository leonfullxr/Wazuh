#!/bin/bash

# Wazuh 4.9 Single-Node Setup Automation Script

# Prompt user for IP addresses for each component
read -p "Enter the IP address for Wazuh components (e.g., 192.168.1.16): " WAZUH_IP

# Step 1: Download SSL certificate generation tool and configuration file
echo "Downloading SSL certificate tool and configuration file..."
curl -sO https://packages.wazuh.com/4.9/wazuh-certs-tool.sh
curl -sO https://packages.wazuh.com/4.9/config.yml

# Step 2: Update config.yml to match the specified structure and IPs
echo "Updating configuration file (config.yml) with specified IPs..."
cat << EOF > ./config.yml
nodes:
  # Wazuh indexer nodes
  indexer:
    - name: wazuh
      ip: "$WAZUH_IP"
    # - name: node-2
    #   ip: "<indexer-node-ip>"
    # - name: node-3
    #   ip: "<indexer-node-ip>"

  # Wazuh server nodes
  # If there is more than one Wazuh server node, each one must have a node_type
  server:
    - name: wazuh-1
      ip: "$WAZUH_IP"
      # node_type: master
    # - name: wazuh-2
    #   ip: "<wazuh-manager-ip>"
    #   node_type: worker
    # - name: wazuh-3
    #   ip: "<wazuh-manager-ip>"
    #   node_type: worker

  # Wazuh dashboard nodes
  dashboard:
    - name: dashboard
      ip: "$WAZUH_IP"
EOF

echo "config.yml has been updated with the specified IP structure."

# Step 3: Generate SSL Certificates
echo "Generating SSL certificates..."
bash ./wazuh-certs-tool.sh -A

# Step 4: Compress certificates and clean up
echo "Compressing certificates..."
tar -cvf ./wazuh-certificates.tar -C ./wazuh-certificates/ .
rm -rf ./wazuh-certificates

# Step 5: Install required package dependencies
echo "Installing package dependencies..."
apt-get update
apt-get install -y debconf adduser procps

# Step 6: Install gnupg and apt-transport-https
echo "Installing gnupg and apt-transport-https..."
apt-get install -y gnupg apt-transport-https

# Step 7: Add Wazuh GPG key and repository
echo "Adding Wazuh GPG key and repository..."
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list

# Step 8: Update package list
echo "Updating package list..."
apt-get update

# Step 9: Install Wazuh components
echo "Installing Wazuh components..."
apt-get install -y wazuh-indexer wazuh-manager filebeat wazuh-dashboard

# Step 10: Configure Wazuh Indexer (opensearch.yml) as per provided image
echo "Configuring Wazuh Indexer (opensearch.yml)..."
cat << EOF > /etc/wazuh-indexer/opensearch.yml
network.host: "$WAZUH_IP"
node.name: "wazuh"
cluster.initial_master_nodes:
  - "wazuh"
  # - "node-2"
  # - "node-3"
cluster.name: "wazuh-cluster"
# discovery.seed_hosts:
#   - "node-1-ip"
#   - "node-2-ip"
#   - "node-3-ip"
node.max_local_storage_nodes: "3"
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer

plugins.security.ssl.http.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.http.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.transport.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.transport.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.http.enabled: true
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.resolve_hostname: false

plugins.security.authcz.admin_dn:
  - "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US"
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.nodes_dn:
  - "CN=wazuh,OU=Wazuh,O=Wazuh,L=California,C=US"
  # - "CN=node-2,OU=Wazuh,O=Wazuh,L=California,C=US"
  # - "CN=node-3,OU=Wazuh,O=Wazuh,L=California,C=US"
plugins.security.restapi.roles_enabled: ["all_access", "security_rest_api_access"]

plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices: [".plugins-ml-model", ".plugins-ml-task", ".opendistro-alerting-config"]

# Option to allow Filebeat-oss 7.10.2 to work
compatibility.override_main_response_version: true
EOF

# Step 11: Deploy Certificates for Wazuh Indexer
echo "Deploying certificates for Wazuh Indexer..."
NODE_NAME=wazuh
mkdir -p /etc/wazuh-indexer/certs
tar -xf ./wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ ./wazuh.pem ./wazuh-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
mv -n /etc/wazuh-indexer/certs/wazuh.pem /etc/wazuh-indexer/certs/indexer.pem
mv -n /etc/wazuh-indexer/certs/wazuh-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
chmod 500 /etc/wazuh-indexer/certs
chmod 400 /etc/wazuh-indexer/certs/*
chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs

# Step 12: Start Wazuh Indexer Service
echo "Starting Wazuh Indexer..."
systemctl daemon-reload
systemctl enable wazuh-indexer
systemctl start wazuh-indexer

# Step 13: Install and Configure Filebeat
echo "Configuring Filebeat..."
curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/4.9/tpl/wazuh/filebeat/filebeat.yml
sed -i "s/hosts: \[\"127.0.0.1:9200\"\]/hosts: [\"$WAZUH_IP:9200\"]/" /etc/filebeat/filebeat.yml
filebeat keystore create
echo "admin" | filebeat keystore add username --stdin --force
echo "admin" | filebeat keystore add password --stdin --force

# Step 14: Download Alert Template for Filebeat
echo "Downloading alert template..."
curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v4.9.1/extensions/elasticsearch/7.x/wazuh-template.json
chmod go+r /etc/filebeat/wazuh-template.json

# Step 15: Install Filebeat Module for Wazuh
echo "Installing Filebeat module..."
curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.4.tar.gz | tar -xvz -C /usr/share/filebeat/module

# Step 16: Deploy Certificates for Filebeat
echo "Deploying certificates for Filebeat..."
NODE_NAME=wazuh-1
mkdir -p /etc/filebeat/certs
tar -xf ./wazuh-certificates.tar -C /etc/filebeat/certs/ ./wazuh-1.pem ./wazuh-1-key.pem ./root-ca.pem
mv -n /etc/filebeat/certs/wazuh-1.pem /etc/filebeat/certs/filebeat.pem
mv -n /etc/filebeat/certs/wazuh-1-key.pem /etc/filebeat/certs/filebeat-key.pem
chmod 500 /etc/filebeat/certs
chmod 400 /etc/filebeat/certs/*
chown -R root:root /etc/filebeat/certs

# Step 17: Configure the Wazuh Indexer Connection in Wazuh Manager
echo "Configuring Wazuh Indexer connection in Wazuh Manager..."
echo 'admin' | /var/ossec/bin/wazuh-keystore -f indexer -k username
echo 'admin' | /var/ossec/bin/wazuh-keystore -f indexer -k password

# Step 18: Start the Wazuh Manager
echo "Starting Wazuh Manager..."
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager

# Step 19: Start Filebeat
echo "Starting Filebeat..."
systemctl daemon-reload
systemctl enable filebeat
systemctl start filebeat

# Step 20: Avoid cluster-related errors by initializing Wazuh Indexer security
echo "Initializing Wazuh Indexer security..."
/usr/share/wazuh-indexer/bin/indexer-security-init.sh

# Step 21: Verify Filebeat output
echo "Testing Filebeat output..."
filebeat test output

# Step 22: Configure Wazuh Dashboard
echo "Configuring Wazuh Dashboard..."
sed -i "s/^server.host:.*/server.host: \"$WAZUH_IP\"/" /etc/wazuh-dashboard/opensearch_dashboards.yml
sed -i "s/^opensearch.hosts:.*/opensearch.hosts: [\"https:\/\/$WAZUH_IP:9200\"]/" /etc/wazuh-dashboard/opensearch_dashboards.yml

# Step 23: Deploy Certificates for Wazuh Dashboard
echo "Deploying certificates for Wazuh Dashboard..."
NODE_NAME=dashboard
mkdir -p /etc/wazuh-dashboard/certs
tar -xf ./wazuh-certificates.tar -C /etc/wazuh-dashboard/certs/ ./dashboard.pem ./dashboard-key.pem ./root-ca.pem
mv -n /etc/wazuh-dashboard/certs/dashboard.pem /etc/wazuh-dashboard/certs/dashboard.pem
mv -n /etc/wazuh-dashboard/certs/dashboard-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
chmod 500 /etc/wazuh-dashboard/certs
chmod 400 /etc/wazuh-dashboard/certs/*
chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs

# Step 24: Start Wazuh Dashboard
echo "Starting Wazuh Dashboard..."
systemctl daemon-reload
systemctl enable wazuh-dashboard
systemctl start wazuh-dashboard

# Step 25: Configure Wazuh API URL in Dashboard settings
echo "Configuring Wazuh API URL in Dashboard..."
WAZUH_CONFIG_FILE="/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml"
if [ -f "$WAZUH_CONFIG_FILE" ]; then
  sed -i "s#url:.*#url: http://$WAZUH_IP:55000/#" "$WAZUH_CONFIG_FILE"
  echo "Updated Wazuh API URL to http://$WAZUH_IP:55000/"
else
  echo "Wazuh configuration file $WAZUH_CONFIG_FILE not found!"
fi

echo "Wazuh 4.9 Single-Node Setup Completed!"