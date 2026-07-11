# Alert Delivery and SaaS Audit Collection

This folder contains two inbound audit-log normalization pipelines. Outbound
alert delivery belongs in the generic webhook or destination-specific
integration guides.

| Task | Guide |
|---|---|
| Normalize and collect Jira audit API exports | [Jira](jira/README.md) |
| Normalize and collect Confluence audit API exports | [Confluence](confluence/README.md) |
| POST selected Wazuh alerts to an HTTPS endpoint | [Generic webhook](../webhook/README.md) |
| Send selected alerts to Splunk SOAR | [Splunk SOAR](../splunk/README.md) |

For SaaS audit collection, maintain pagination and a durable fetch checkpoint
outside the normalizer scripts. Verify record counts before and after
conversion, restrict access to identity and permission-change data, and rotate
consumed NDJSON files.
