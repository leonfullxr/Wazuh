# Recommended Approaches for FIM within Containerized Environments

## Introduction
Basically, our implementation of container security will be done at two different layers:

1.- The infrastructure layer

In order to monitor the Docker host or the K8s node, we do have a solution that makes use of different monitoring mechanisms:

APIs integration: Being able to pull data directly from the Docker engine API or from the K8s API. Here you will find a guide on how to accomplish this step by step: https://documentation.wazuh.com/4.0/docker-monitor/monitoring_containers_activity.html 

When the infrastructure is self-managed (on-premises): We typically deploy the Wazuh agent to the Docker host or K8s node. Then, the agent monitors the host itself (looking for threats or anomalies) and communicates with the Docker and K8s APIs. Here you will find a guide on how to accomplish this step by step: https://documentation.wazuh.com/4.0/docker-monitor/monitoring_docker_server.html 
and for the deployment: https://documentation.wazuh.com/4.0/deploying-with-kubernetes/index.html 

When the infrastructure is hosted (e.g. Google GKE, Amazon EKS, etc.): We do connect one of the Wazuh agents (sometimes even the manager directly), to the cloud provider, downloading the audit logs (which are forwarded to the Wazuh manager for analysis): https://wazuh.com/blog/monitoring-gke-audit-logs/ 

Example of security alerts at an infrastructure level:

A Docker image is modified.

A container is running in privileged mode.

A user runs a command inside a container.

A new pod is created.

K8s network configuration is changed.

A new application is installed on the host.

Vulnerabilities are detected on the host.

Hardening checks fail for the host.

2.- The container layer

In order to monitor the containers we do usually go with one of these two options:

Run the Wazuh agent in a DaemonSet container/pod: This agent will access the file system of other containers, in order to read log messages, detect changes to configuration files, get a list of applications installed, run hardening checks, etc.

However, this is not officially supported yet and FIM is not available.

Run the Wazuh agent directly in the host: Same features as described above. I do recommend this option: https://documentation.wazuh.com/current/docker-monitor/monitoring_docker_server.html

If the installation of the agent in the host, is feasible, then you should:

Install the Wazuh Agent and connect it to the Wazuh Manager: https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html

Configure the Docker listener: https://documentation.wazuh.com/current/user-manual/capabilities/container-security/monitoring-docker.html

Configure FIM for the docker volumes: https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/how-to-configure-fim.html

Then you can monitor extra commands as docker ps, or other docker commands with Wazuh: https://wazuh.com/blog/docker-container-security-monitoring-with-wazuh/

But inside the Docker container you can not run Wazuh Agents by default, so when running it (as daemon set) you can not make the most of all the capabilities from the agent. For Instance, FIM will not be available, but you will be able to read logs inside that container.

If you want to monitor the files of the containers within the containers itself, a good way would be to do it through the centralized configuration https://wazuh.com/blog/agent-groups-and-centralized-configuration/#:~:text=This%20enables%20you%20to%20apply,to%20agents%20within%20a%20group  although I would need to run some tests to ensure this will work and come up with a detailed answer.

## Installation of the Wazuh agent in a Docker Host
Run the Wazuh agent directly in the host: https://documentation.wazuh.com/current/docker-monitor/monitoring_docker_server.html

By doing so, you can perform FIM, log collection, and all the Wazuh capabilities.

## Daemonset Installation
The DaemonSet option is when you cannot install an agent on the host and you need to monitor the container layer.

### Wazuh Agent Dockerized Installation
```xml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: wazuh-agent
  namespace: wazuh
  labels:
    k8s-app: wazuh-agent
spec:
  selector:
    matchLabels:
      name: wazuh-agent
  template:
    metadata:
      labels:
        name: wazuh-agent
    spec:
      containers:
      - name: wazuh-agent 
        image: wazuh-agent:4.1.4
        env:
        - name: WAZUH_MANAGER_IP
          value: "192.168.1.240"
        - name: WAZUH_AGENT_GROUP
          value: "kubernetes"
        volumeMounts:
        - name: nginx-logs
          mountPath: /var/log/wazuh/nginx/
      volumes:
      - name: nginx-logs
        hostPath:
          path: /var/log/kubernetes/nginx/
```

```xml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-test-app
  namespace: wazuh
  labels:
    k8s-app: nginx-test
spec:
  replicas: 3
  selector:
    matchLabels:
      name: nginx-app
  template:
    metadata:
      labels:
        name: nginx-app
    spec:
      containers:
      - name: nginx 
        image: nginx 
        ports:
        - containerPort: 80
        volumeMounts:
        - name: nginx-logs
          mountPath: /var/log/nginx/
      volumes:
      - name: nginx-logs
        hostPath:
          path: /var/log/kubernetes/nginx/
```