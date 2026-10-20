# Wazuh agent on a base image you control. Use the official wazuh/wazuh-agent
# image unless a base-image policy or an internal registry rules it out.
FROM debian:12-slim

# Match the manager version or stay below it; agents newer than the manager
# are not supported.
ARG WAZUH_VERSION=4.14.9-1

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg procps \
 && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
    | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends "wazuh-agent=${WAZUH_VERSION}" \
 && apt-get purge -y curl gnupg \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
