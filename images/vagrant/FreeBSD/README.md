# FreeBSD 14
This folder contains a Vagrant file for running a VM for FreeBSD14, and some instructions for installing a custom Wazuh Agent version.

# Wazuh Agent 4.11.2 Installation on FreeBSD 14

This README covers the basic steps to install and configure a specific Wazuh Agent package (4.11.2) on FreeBSD 14. Adjust paths, URLs, and IPs as needed for your environment.

## Prerequisites

Ensure you have root (or sudo) access. You’ll need the following packages:

```sh
sudo pkg install -y pkgconf git cmake gmake gcc bash libinotify sqlite3
```

---

## Downloading the Wazuh Agent Package

Locate the FreeBSD 14 binary for **wazuh-agent-4.11.2.pkg**. In this example, it’s hosted on an OPNsense mirror:

```
https://mirror.uvensys.de/opnsense/FreeBSD:14:amd64/snapshots/latest/All/wazuh-agent-4.11.2.pkg
```

You can substitute that URL with any other mirror or an older `.pkg` version you need (e.g., 4.11.2).

---

## Installing Wazuh Agent

1. **Add the `.pkg` file**
   Replace the URL below if you’re using a different mirror or version:

   ```sh
   sudo pkg add https://mirror.uvensys.de/opnsense/FreeBSD:14:amd64/snapshots/latest/All/wazuh-agent-4.11.2.pkg
   ```

2. **Verify the installation**:

   ```sh
   pkg info | grep wazuh-agent
   ```

   You should see something like:

   ```
   wazuh-agent-4.11.2             Security tool to monitor and check logs and intrusions (agent)
   ```

---

## Configuration

1. **Sync local time to the agent**
   This ensures that Wazuh’s logs and timestamps match your system timezone:

   ```sh
   cp /etc/localtime /var/ossec/etc/
   ```

2. **Edit the agent configuration**
   Open `/var/ossec/etc/ossec.conf` and update the `<server>` block to point at your Wazuh Manager:

   ```xml
   <server>
     <address>WAZUH-MANAGER-IP-ADDRESS</address>
     <protocol>tcp</protocol>
   </server>
   ```

   Replace `WAZUH-MANAGER-IP-ADDRESS` with your manager’s IP or hostname.

---

## Enabling the Agent at Boot

By default, Wazuh Agent ships with an init script at `/usr/local/etc/rc.d/wazuh-agent`. To have it start at system boot:

```sh
sysrc wazuh_agent_enable="YES"
```

This adds the line below to `/etc/rc.conf`:

```
wazuh_agent_enable="YES"
```

### (Optional) Create a Symlink for a Custom Service Name

If you’d rather not modify the original script name, you can symlink it:

```sh
ln -s /usr/local/etc/rc.d/wazuh-agent /usr/local/etc/rc.d/wazuh-agent.sh
```

You can then use:

```sh
service wazuh-agent.sh start
```

---

## Starting the Agent

```sh
service wazuh-agent start
```

You should see:

```
Starting Wazuh Agent:
```

---

## Checking the Agent Status

```sh
service wazuh-agent status
```

A healthy agent will report something like:

```
wazuh-modulesd is running...
wazuh-logcollector is running...
wazuh-syscheckd is running...
wazuh-agentd is running...
wazuh-execd is running...
```

---

## Removing Duplicate Agents (Optional)

If you enroll an agent multiple times, you may see errors about duplicate names. On the Wazuh Manager, remove the old entry:

```sh
/var/ossec/bin/manage_agents -r <agent_id>
```

Replace `<agent_id>` with the numerical ID of the agent you want to remove.

That’s it! Your Wazuh Agent 4.11.2 should now be installed, configured, and running on FreeBSD 14.

