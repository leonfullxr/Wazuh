#!/bin/sh
# Render a minimal ossec.conf, start the agent, and stop it cleanly on SIGTERM.
# What the agent collects (FIM, log files) comes from the group agent.conf on
# the manager, so this file only covers connection and enrollment.
set -eu

: "${WAZUH_MANAGER:?set WAZUH_MANAGER to the address agents send events to (1514)}"
REGISTRATION_SERVER="${WAZUH_REGISTRATION_SERVER:-$WAZUH_MANAGER}"
AGENT_NAME="${WAZUH_AGENT_NAME:-$(hostname)}"
PASS_FILE="${WAZUH_AUTHD_PASS_FILE:-/run/secrets/wazuh/authd.pass}"
OSSEC=/var/ossec

GROUPS_XML=""
[ -n "${WAZUH_AGENT_GROUP:-}" ] && GROUPS_XML="<groups>${WAZUH_AGENT_GROUP}</groups>"

# Keep only the agent key on a node-local volume, so the agent ID survives pod
# restarts while binaries and defaults always come from the current image.
# The agent replaces client.keys when it enrolls (a symlink does not survive),
# so the key is restored at start and copied back periodically and on stop.
KEYS="$OSSEC/etc/client.keys"
save_keys() {
  if [ -n "${WAZUH_STATE_DIR:-}" ] && [ -s "$KEYS" ] && ! cmp -s "$KEYS" "$WAZUH_STATE_DIR/client.keys"; then
    cp "$KEYS" "$WAZUH_STATE_DIR/client.keys"
  fi
}
if [ -n "${WAZUH_STATE_DIR:-}" ] && [ -s "$WAZUH_STATE_DIR/client.keys" ]; then
  install -m 0640 -o wazuh -g wazuh "$WAZUH_STATE_DIR/client.keys" "$KEYS"
fi

# etc/authd.pass is where the agent looks by default.
if [ -f "$PASS_FILE" ]; then
  install -m 0640 -o root -g wazuh "$PASS_FILE" "$OSSEC/etc/authd.pass"
fi

# Syscollector, SCA and rootcheck would describe this container, not the node.
# A group agent.conf can still turn them back on.
cat > "$OSSEC/etc/ossec.conf" <<EOF
<ossec_config>
  <client>
    <server>
      <address>${WAZUH_MANAGER}</address>
      <port>${WAZUH_MANAGER_PORT:-1514}</port>
      <protocol>tcp</protocol>
    </server>
    <enrollment>
      <enabled>yes</enabled>
      <manager_address>${REGISTRATION_SERVER}</manager_address>
      <port>${WAZUH_REGISTRATION_PORT:-1515}</port>
      <agent_name>${AGENT_NAME}</agent_name>
      ${GROUPS_XML}
    </enrollment>
  </client>
  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>
  <syscheck>
    <disabled>no</disabled>
  </syscheck>
  <rootcheck>
    <disabled>yes</disabled>
  </rootcheck>
  <wodle name="syscollector">
    <disabled>yes</disabled>
  </wodle>
  <sca>
    <enabled>no</enabled>
  </sca>
  <logging>
    <log_format>plain</log_format>
  </logging>
</ossec_config>
EOF
chown root:wazuh "$OSSEC/etc/ossec.conf"
chmod 0640 "$OSSEC/etc/ossec.conf"

# Stale pid files from an unclean stop make wazuh-control refuse to start.
rm -f "$OSSEC"/var/run/*.pid

trap '"$OSSEC/bin/wazuh-control" stop; save_keys; exit 0' TERM INT
"$OSSEC/bin/wazuh-control" start
(while sleep 30; do save_keys; done) &
tail -F "$OSSEC/logs/ossec.log" &
wait $!
