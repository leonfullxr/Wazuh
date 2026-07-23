I've run several tests and managed to create a Wazuh Agent daemonset but there are some conditions for this to work:

The daemonset will run in Docker only.

You need to be able of managing the Worker nodes.

In case you want to monitor specific directories with it, you would need to configure shared volumes and monitor files from it/them.

Having this said this would be the dockerfile:
```Dockerfile
 Wazuh App Copyright (C) 2021 Wazuh Inc. (License GPLv2)
FROM python:3.9-slim-buster
# Dependencies
RUN apt-get update && \
    apt-get install curl procps apt-transport-https lsb-release -y &&\
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* &&\
    mkdir /scripts /config\
    pip3 install docker
# Install the Wazuh agent
RUN curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.1.5-1_amd64.deb && dpkg -i ./wazuh-agent.deb
# Entrypoint
ADD entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
```

This would be the entrypoint.sh:
```bash
#!/bin/bash

# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. .
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

pip3 install docker

echo "<ossec_config><wodle name=\"docker-listener\"><disabled>no</disabled></wodle></ossec_config>" >> /var/ossec/etc/ossec.conf

/var/ossec/bin/agent-auth -m YOUR_MANAGER_IP
sed -i 's/MANAGER_IP/YOUR_MANAGER_IP/g' /var/ossec/etc/ossec.conf
/var/ossec/bin/ossec-control restart 

sleep infinity
```

Make sure to replace YOUR_MANAGER_IP with your actual DNS/LB/IP address from the Wazuh Manager and put both files in the same directory.

Then run next command to create the image: 
```bash
docker build -t wazuh-daemonset:0.1
```

Now you would be ready to execute the daemonset. The daemonset.yaml content would be this:
```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: wazuh-daemonset
  namespace: default
  labels:
    k8s-app: wazuh-daemonset
spec:
  selector:
    matchLabels:
      name: wazuh-daemonset
  template:
    metadata:
      labels:
        name: wazuh-daemonset
    spec:
      tolerations:
      # this toleration is to have the daemonset runnable on master nodes
      # remove it if your masters can't run pods
      - key: node-role.kubernetes.io/master
        effect: NoSchedule
      containers:
      - name: wazuh-daemonset
        image: wazuh-daemonset:0.1
        resources:
          limits:
            memory: 200Mi
          requests:
            cpu: 100m
            memory: 200Mi
        volumeMounts:
        - name: docker
          mountPath: /var/run/docker.sock
        - name: varlibdockercontainers
          mountPath: /var/lib/docker/containers
      terminationGracePeriodSeconds: 5
      volumes:
      - name: varlibdockercontainers
        hostPath:
          path: /var/lib/docker/containers
      - name: docker
        hostPath:
          path: /var/run/docker.sock
```

And applied it with kubectl:
```bash
kubectl apply -f daemonSet.yaml
```

After this, you should have a new connected Agent added into your Wazuh Manager.