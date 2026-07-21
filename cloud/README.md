# Cloud Infrastructure and Log Ingestion

This section is for administrators ingesting AWS, Azure, and Google Cloud
security data or operating a hosted Wazuh environment. It covers provider
identity, log delivery, Wazuh collectors, state tracking, verification, and
least-privilege dashboard access.

Cloud modules consume logs only after the provider has delivered them to S3,
Log Analytics, Blob Storage, Microsoft Graph, or Pub/Sub. Verify the
provider-side pipeline first, then the Wazuh module, decoder/rule output, and
indexing as separate layers.

## Contents

| Document | Description |
|---|---|
| [aws.md](aws.md) | AWS log ingestion with the `aws-s3` wodle: CloudTrail, GuardDuty, VPC Flow Logs, CloudWatch, Security Lake; IAM/credential setup, Kubernetes secret mounts, state-database gotchas, debugging |
| [azure.md](azure.md) | Azure log ingestion: `azure-logs` wodle (Log Analytics, Graph, blob storage) and the native `ms-graph` module (Defender, Entra ID Protection); app registration, admin consent, indexer mapping conflicts |
| [gcp-pubsub.md](gcp-pubsub.md) | Google Cloud log ingestion via Pub/Sub with Application Default Credentials -- no service account key files; subscriber script, localfile monitor, base rule |
| [wazuh-cloud-service.md](wazuh-cloud-service.md) | Wazuh Cloud SaaS from the customer side: credential types, `/api/wazuh/` and `/api/elastic/` endpoints, hot vs cold storage stages, downloading archive data with `wcloud-cli` |
| [rbac-dashboards.md](rbac-dashboards.md) | Letting operators save/edit dashboards and generate reports without admin rights (OpenSearch Security roles, reporting system indices) |

## Quick Orientation

All three provider integrations follow the same shape: create a low-privilege identity on the provider side, point a Wazuh module (or a small subscriber script) at the log source, and let the events flow into `analysisd` as JSON where provider-specific rule groups (`amazon`, `azure`, `gcp`) pick them up.

- Provider-side services must be configured to *deliver* logs first (CloudTrail trail to S3, Azure diagnostics to Log Analytics/blob, Cloud Logging sink to Pub/Sub) -- Wazuh only consumes.
- Every module keeps local state (SQLite databases or offset markers); "first-run" options like `only_logs_after`, `time_offset`, and `only_future_events` are ignored on subsequent runs until that state is cleared.
- Debugging is uniform: `wazuh_modules.debug=2` in `local_internal_options.conf`, or run the wodle binary by hand with `--debug 2`.

## Quick reference

| Task or symptom | Guide |
|---|---|
| Collect CloudTrail, GuardDuty, VPC Flow Logs, or Security Lake | [AWS](aws.md) |
| Collect Log Analytics, Blob, Defender, or Entra events | [Azure](azure.md) |
| Route Cloud Logging or GKE audit logs through Pub/Sub | [Google Cloud Pub/Sub](gcp-pubsub.md) |
| Use Wazuh Cloud API endpoints or archive storage | [Wazuh Cloud service](wazuh-cloud-service.md) |
| Let non-admin users edit dashboards or run reports | [Dashboard RBAC](rbac-dashboards.md) |
