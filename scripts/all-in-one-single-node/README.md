# All-in-one single-node deployment

Scripts to install a complete Wazuh stack (indexer + manager + dashboard +
filebeat) on a single host, wrapping the official installation assistant.

## install-aio.sh (recommended)

Version-agnostic unattended installer. Pass the target Wazuh version as the
only argument:

```bash
sudo bash install-aio.sh 4.12
```

What it does:

1. Pre-flight checks: root privileges, internet connectivity, and that the
   requested version exists on `packages.wazuh.com`.
2. Detects the package manager (`apt`/`yum`/`zypper`) and CPU architecture
   (x86_64 or ARM; on ARM it patches `wazuh-install.sh` dependencies).
3. Downloads `config.yml` and `wazuh-install.sh` for the requested version and
   fills in the host IP for indexer, manager, and dashboard nodes.
4. Generates self-signed certificates and random passwords.
5. Installs the indexer, server (with Filebeat), and dashboard in order,
   printing the generated passwords and a per-service status summary.
6. Optionally runs `filebeat test output`.
7. Optionally resets the indexer `admin` password to `admin` using
   `securityadmin.sh` and updates the Filebeat and Wazuh keystores. **Lab use
   only - never do this on a production system.**

At the end, the dashboard is available at `https://<host-ip>`.

## setup.sh

Older, Wazuh 4.9-specific variant. Prompts for the host IP, generates
certificates with `wazuh-certs-tool.sh`, and installs the components
step by step. Kept for reference; prefer `install-aio.sh`.
