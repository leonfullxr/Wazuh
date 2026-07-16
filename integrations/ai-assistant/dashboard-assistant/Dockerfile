# Bake OpenSearch Dashboards Assistant plugins into the Wazuh dashboard image (V3.1d).
# The wazuh-dashboard base image has curl but not tar — fetch/extract on Debian.
ARG WAZUH_VERSION=4.14.5

FROM wazuh/wazuh-dashboard:${WAZUH_VERSION} AS osd-meta
RUN grep '"version":' /usr/share/wazuh-dashboard/package.json \
    | head -1 | cut -d'"' -f4 > /tmp/osd-version

FROM debian:bookworm-slim AS osd-plugins
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tar \
    && rm -rf /var/lib/apt/lists/*
COPY --from=osd-meta /tmp/osd-version /tmp/osd-version
RUN set -eux; \
    OSD_VER="$(cat /tmp/osd-version)"; \
    curl -fsSL \
      "https://artifacts.opensearch.org/releases/bundle/opensearch-dashboards/${OSD_VER}/opensearch-dashboards-${OSD_VER}-linux-x64.tar.gz" \
      -o /tmp/osd.tgz; \
    tar -xzf /tmp/osd.tgz -C /tmp; \
    mkdir -p /out; \
    mv "/tmp/opensearch-dashboards-${OSD_VER}/plugins/assistantDashboards" /out/assistantDashboards; \
    mv "/tmp/opensearch-dashboards-${OSD_VER}/plugins/mlCommonsDashboards" /out/mlCommonsDashboards; \
    rm -rf /tmp/osd.tgz "/tmp/opensearch-dashboards-${OSD_VER}"

FROM wazuh/wazuh-dashboard:${WAZUH_VERSION}
USER root
COPY --from=osd-plugins /out/assistantDashboards /usr/share/wazuh-dashboard/plugins/assistantDashboards
COPY --from=osd-plugins /out/mlCommonsDashboards /usr/share/wazuh-dashboard/plugins/mlCommonsDashboards
RUN chown -R wazuh-dashboard:wazuh-dashboard \
      /usr/share/wazuh-dashboard/plugins/assistantDashboards \
      /usr/share/wazuh-dashboard/plugins/mlCommonsDashboards \
    && chmod -R 750 \
      /usr/share/wazuh-dashboard/plugins/assistantDashboards \
      /usr/share/wazuh-dashboard/plugins/mlCommonsDashboards
USER wazuh-dashboard
