# Wazuh
Wazuh configuration, setup and scripts. This repository serves as my personal notes and configurations that I have created for **deployment and testing**

Please refer to the official integration repository which is mantained and updated: https://github.com/wazuh/integrations

**Disclaimer**: The integrations and content within this repository are provided "as is" without warranty of any kind, express or implied. Users are responsible for evaluating the security, quality, and compatibility of any code or configurations they choose to utilize from this repository. I do not guarantee the absence of vulnerabilities, errors, or suitability for any particular purpose.

## Repository structure

I will expand this repository in the near future, but for now, I will have the following directories:
- containerization --> Here I will have everything related to containerization, such as Docker and Kubernetes configurations.
    - Docker --> Here I will have single-node and multi-node Docker configurations, with HTTP and reverse proxy configurations (Traefik), and so on.
- scripts --> Here I will have a few scripts, such as RestfulAPI connections, 
- rules --> Here I will have custom wazuh rule configurations, mostly for FortiGate routers, for now.
- decoders --> Here I will have custom wazuh decoder configurations, mostly for FortiGate routers, for now.
- integrations --> Here I will have custom wazuh integration configurations, such as LDAPS, custom API connections, custom alerts integration, LLM integration, etc.

## Contributing

Feel free to fork/edit/copy and do whatever you want with the files, although always at your own risk (some configurations might need further modifications, feel free to contact me if necessary).
