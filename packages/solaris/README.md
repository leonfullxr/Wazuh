# Wazuh Agent Cross-Compilation Guide: Solaris 10 & 11

This document outlines the procedure for compiling native Wazuh Agent packages for Oracle Solaris 10 and Solaris 11 from a modern Linux host. 

## Environment Specifications
* **Host Operating System:** Debian GNU/Linux 12 (bookworm)
* **Target Wazuh Version:** v4.14.5
* **Architecture:** i386
* **Build Mechanism:** Vagrant with VirtualBox provider

## Generated Artifacts
Upon successful completion, the following artifacts are generated:
* **Solaris 10:** Legacy SVR4 Package (`wazuh-agent_v4.14.5-sol10-i386.pkg`)
* **Solaris 11:** Image Packaging System Archive (`wazuh-agent_v4.14.5-sol11-i386.p5p`)

## Part 1: Host Preparation

1. **Clone the Wazuh repository and check out the target version:**
   ```bash
   git clone https://github.com/wazuh/wazuh
   cd wazuh/packages
   git checkout v4.14.5
   ```

2. **Navigate to the Solaris package directory:**
   ```bash
   cd solaris
   ```

## Part 2: Building for Solaris 10

Solaris 10 builds smoothly without major interventions. 

1. **Stage the Solaris 10 build scripts:**
   ```bash
   cp -r solaris10 package_generation/src/
   cd package_generation
   ```

2. **Spin up the VM and compile the package:**
   ```bash
   vagrant --branch-tag=v4.14.5 up solaris10_cmake
   ```
   *(Note: This process takes 15-30 minutes. The resulting `.pkg` file will be deposited in the `src/` directory.)*

3. **Tear down the build environment:**
   ```bash
   vagrant destroy solaris10_cmake -f
   ```

## Part 3: Building for Solaris 11 (SSL Certificate Patch)

The base image for Solaris 11 contains expired root SSL certificates (a common issue post-2021). If the build script is run unmodified, `curl` will throw `Error 60` or `Error 77` and fail to download the required C++ dependencies (like `cJSON` and `openssl`).

1. **Stage the Solaris 11 build scripts:**
   ```bash
   # From the wazuh/packages/solaris directory
   cp -r solaris11 package_generation/src/
   cd package_generation
   ```

2. **Apply the SSL Bypass Patch:**
   Inject a `.curlrc` configuration into the build script to force `curl` to ignore the expired local certificates when downloading dependencies.
   ```bash
   sed -i '2i echo "insecure" > ~/.curlrc' src/solaris11/generate_wazuh_packages.sh
   ```

3. **Spin up the VM and compile the package:**
   ```bash
   vagrant --branch-tag=v4.14.5 up solaris11_cmake
   ```
   *(The resulting `.p5p` file will be deposited in the `src/` directory.)*

4. **Tear down the build environment:**
   ```bash
   vagrant destroy solaris11_cmake -f
   ```

## Part 4: Installation Instructions

Transfer the generated packages to your target Solaris servers (e.g., via `scp` to `/tmp/`). **Do not use the same command for both operating systems.**

### Installing on Solaris 10
Solaris 10 uses the legacy SVR4 package manager. Run the following as root:
```bash
pkgadd -d /tmp/wazuh-agent_v4.14.5-sol10-i386.pkg
```

### Installing on Solaris 11
Solaris 11 uses the modern Image Packaging System (IPS). You must use the `-g` flag to point directly to the file archive. Run the following as root:
```bash
pkg install -g /tmp/wazuh-agent_v4.14.5-sol11-i386.p5p wazuh-agent
```

### Post-Installation (Both OS Versions)
The package installer handles the creation of the `wazuh` user/group and registers the daemon. You must manually configure and start the agent:

1. Edit `/var/ossec/etc/ossec.conf` and update `<server><address>` with your Manager IP.
2. Register the agent using `/var/ossec/bin/agent-auth -m <MANAGER_IP>`.
3. Start the service: `/var/ossec/bin/wazuh-control start`.
