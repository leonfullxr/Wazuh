# Private AI SOC deployment

This directory defines an internal HTTPS service in an existing VPC. Supply
existing private subnets, route tables, the ALB certificate, restricted analyst
and identity egress ranges, the regional S3 and DynamoDB managed prefix list IDs,
pinned per-site indexer/CA settings, approved model
and guardrail ARNs, private ECR image digest, content commit, and an operations
alarm topic through the protected deployment system. The task image URI must
be an immutable digest in the same account and Region.
The ADOT source image is pinned by digest in the platform tool lock. Promote that
exact image manifest to the private `${deployment_name}-adot-collector` ECR
repository and supply its `sha256:` digest as `adot_collector_digest`; tasks do
not pull a public image at runtime.

The module creates no VPC, public subnet, NAT gateway, public indexer route,
customer VPN, Terraform backend, or plaintext output. Before any later live
apply, the platform owner must configure its organization-approved encrypted
remote Terraform state and review state access. ALB OIDC client-secret input is
sensitive; the ALB listener API requires its value, so the deployment state
backend must be encrypted and tightly restricted. Do not check values into
`.tfvars`, CI logs, plans, or outputs.

## Remote state init

The root module declares a partial `backend "s3"` block in `versions.tf` with
`encrypt = true` and S3 native locking (`use_lockfile = true`). Supply bucket,
key, Region, and any organization-specific locking settings at init time only;
never commit account-specific backend values to git.

```text
terraform -chdir=infra init \
  -backend-config=backend.hcl
```

Keep `backend.hcl` (or equivalent `-backend-config` files) outside git alongside
deployment `*.tfvars`. `infra/.gitignore` excludes `*.tfvars` and local state
artifacts. Offline validation uses `terraform init -backend=false` via
`make infra-check`.

## Persistent foundation and hourly session

This root keeps one Terraform state so existing production resource addresses
and defaults remain stable. `enable_session_resources` defaults to `true`.
After a session, create and review a plan with that value set to `false`, then
apply the saved plan using the same backend and variable files. This removes
the interface and gateway endpoints, ALB, service tasks, and scheduled archive
worker while retaining the KMS keys, secrets, encrypted state guidance,
DynamoDB, evidence/archive and invocation buckets, queues, log groups, IAM
roles, budgets, alarms, and CloudTrail configuration. The application role's
session policy is removed too, so it cannot invoke Bedrock while its endpoint
is absent. Moved blocks preserve old state addresses when upgrading from the
existing full root. Re-enable the session only after reviewing a new plan.

Run `make check-session-teardown` against the configured remote state after the
apply. It fails if any Terraform-managed session resource remains or if the
required foundation inventory is missing. Lab hosts, manually created identity
resources, certificates, and shared SNS topics are outside this root; check
them using the operator inventory in `docs/operations/continuity.md`. Full
destruction is a separate, data-destructive drill described there.

Fargate has no public IP and admits application traffic only from the internal
ALB security group. The task security group allows VPC TLS/DNS plus each
explicit private indexer CIDR and port. Application-side ALB assertion
verification fetches keys from the documented regional URL
`https://public-keys.auth.elb.<region>.amazonaws.com/<key-id>` ([AWS ALB OIDC
documentation](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html),
checked 2026-10-07). This endpoint has no VPC interface endpoint. Every
`alb_public_key_egress_mode` requires `alb_public_key_egress_cidrs` as exact
`/32` or `/128` destination host routes. In proxy mode these are the in-VPC
proxy addresses; direct modes use resolved destination addresses. The task
security group can enforce only IP and TCP 443. For live qualification
(`qualification_profile = true`), proxy mode is required by default. Set
`qualification_proxy_allowed_hosts` to the exact regional ALB key host, OIDC
issuer host, and MCP JWKS host. The reference Squid rules in
`infra/proxy/squid-qualification.conf` allow HTTPS CONNECT only to exact hosts
listed in `/etc/squid/qualification-allowed-hosts.txt`, and deny arbitrary
hosts, ports, and non-CONNECT traffic. The reference listener uses TLS and
requires a certificate trusted by the ECS task runtime. Restrict the proxy
security group's TCP 443 ingress to the service task security group; do not
expose this listener publicly or to the full VPC. Squid `dstdomain` entries
without a leading dot match the exact hostname, while leading-dot entries also
match subdomains ([Squid ACL documentation](https://www.squid-cache.org/Doc/config/acl/),
checked 2026-10-07). Populate that file from
`terraform output -json qualification_proxy_required_hosts`; review it whenever
an issuer, JWKS, or AWS Region changes. The CONNECT proxy checks host and port,
not TLS SNI or URL paths. The application requests the fixed regional key URL
and path; the ALB key host must not be used for unrelated application traffic.
The ALB's native OIDC action cannot use an HTTP CONNECT proxy, so qualification
requires its IdP to be reachable inside the VPC (`idp_in_vpc = true`). Direct
public IdP routing requires `allow_unqualified_direct_identity_egress = true`,
an explicit exception that does not meet the qualification network requirement.
Production `nat` and `corporate` modes remain available for non-qualification
deployments and restrict destination IP and TCP 443 only; security groups
cannot enforce DNS names, TLS SNI, or URL paths. `identity_egress_cidrs` also
requires individual `/32` or `/128` destinations. Tasks fetch MCP bearer JWKS
from the pinned `mcp_jwks_uri` input (for example a Keycloak
`/protocol/openid-connect/certs` URL, which may differ from `oidc.issuer` when
the issuer includes a realm path). Browser and MCP public URLs use
`service_hostname` (the ACM certificate name), not the ALB DNS name. Set
`idp_in_vpc` when the issuer and JWKS are reachable through the VPC CIDR, or
configure the task's separate `mcp_jwks_https_proxy` /
`SOC_MCP_JWKS_HTTPS_PROXY` value when JWKS must traverse the allowlisting proxy.
Leave the latter empty for in-VPC JWKS.
Interface endpoints cover ECR API/DKR, CloudWatch Logs/metrics, KMS, Secrets
Manager, SQS, Bedrock Runtime, and X-Ray. Every interface endpoint has an
action/resource policy; metric publication
is limited to `AISOC/Service`. By default each interface endpoint is placed in
every `private_subnet_ids` entry (multi-AZ resilience, one ENI per subnet per
hour). For ephemeral qualification only, set `qualification_profile = true` and
optionally set `qualification_interface_endpoint_subnet_ids` to one (or a few)
private subnet IDs to cut PrivateLink hourly ENI cost at the expense of AZ
fault tolerance; production must leave that list empty. S3 and DynamoDB use
gateway endpoints. ECR image pulls include the S3 layer bucket route. Bedrock
invocation is model-ARN allowlisted, requires the pinned guardrail and source
VPC endpoint, and omits streaming actions. The ADOT sidecar receives gRPC spans
on task-local port 4317 and exports to X-Ray through its private endpoint.
Fixture Compose uses a debug-only exporter with no host receiver port. A
separate scheduled ECS task drains audit and feedback SQS into conditional,
encrypted S3 archive writes. Set `enable_audit_archive_schedule = false`, drain
both queues and their DLQs, and verify all queue depths before removing session
networking.

When `qualification_profile = true`, Terraform writes a versioned resource map
to `qualification-maps/resource-map.json` and exposes its exact bucket, key,
version ID, and SHA-256 as `qualification_resource_map_pin`. The sealed service
configuration carries that pin. The map records the audit evidence bucket and
KMS key, current trail and invocation-log settings, exact archive consumer
definition/image/role, and the service plus optional public-isolated subnet and
route table IDs. Supply the existing public-isolated subnet and route table IDs
in `qualification_public_isolated_subnet_ids` and
`qualification_public_isolated_route_table_ids`; this root associates the S3
gateway endpoint with those route tables but does not create or alter their
routes. These IDs must be distinct from the service subnet and route-table
IDs. The resource map pins the dedicated isolated task security group and its
shared isolated-endpoint security group. That task group permits HTTPS only to
the regional S3 managed prefix list and the ECR, Logs, Secrets Manager, and KMS
interface endpoints; the Bedrock Runtime endpoint remains reachable only from
the service task group. The service task group also has explicit S3 and DynamoDB
prefix-list egress for uploads, ECR image layers, and task state access.
The application writes only under `qualification/`; the archive
consumer has a separate `events/qualification/` output grant. Bucket policy
denies deletion/version deletion for both paths and rejects writes without
`If-None-Match: *`. The bucket boundary permits writes to the application
prefix only from the application role, and that role is explicitly denied
access to the consumer output path. The gateway policy's prefix contract lives
in `infra/qualification_evidence.tf`; it includes both production consumer
write prefixes (`events/` and `feedback/`) and the qualification paths.

With CloudTrail enabled, log-file validation remains on and its default
management-event coverage includes changes to the invocation-log bucket policy
and logging configuration. `scripts/qualification/settings_journal.py` persists
a durable, mode-0600 journal. `settings_session.py` applies the shared lifecycle
to CloudTrail selectors and X-Ray sampling rules, recording the exact prior and
requested settings and retaining restore obligations until restoration
succeeds. The S3 selector adapter keeps existing management selectors and adds only the app
qualification prefix plus that run's consumer output prefix. It refuses
unsupported AdvancedEventSelectors and selector-limit cases. A two-placement
same-image canary is available as `python -m ai_soc.qualification.network_canary`
with bucket, KMS key, account, session, run, placement, and typed evidence paths
from the resource map and registered run. The verifier reads only the event-provided
S3 version, hashes its body, and checks the PutObject event's writer role, task
context, version, and digest-validated trail record. `measured_delivery_budget_seconds` derives a
bounded event-plus-digest collection interval from both successful canaries
and returns no budget if proof is missing or the session deadline cannot fit.
The invocation bucket policy
permits Bedrock service delivery only with the configured source-account and
source-ARN conditions, and denies other principals' writes and deletion on
that prefix. Qualification certification remains disabled in the resource map
because no account canary has been executed. Long one-off probes can use
`python -m ai_soc.qualification.probe_health --timeout-seconds N -- <probe>`
inside the pinned service image. The wrapper serves liveness while the probe
runs, serves readiness only after the probe creates
`AI_SOC_PROBE_READY_FILE`, and bounds execution to 900 seconds. Terraform
configures this evidence path; this repository change does not run canaries or
apply account changes.

Each site receives its own asymmetric KMS signing key, a version-pinned CA
secret, explicit Wazuh JWT audience/issuer, role mapping, DLS attestation,
mapping profile, and private destination ranges. These settings still require
the owning Wazuh and network teams to validate against a synthetic site before
live use. The ECS service stays at a minimum of two Fargate tasks; ALB idle time
is 150 seconds, target drain is 160 seconds, and task stop grace is 120 seconds.
Fargate task definitions mount a task-level ephemeral volume at `/tmp` (not
`linuxParameters.tmpfs`) so `readonlyRootFilesystem` stays enabled.

The ALB sends `/mcp` and protected-resource metadata directly to application
bearer validation. Browser routes use the ALB OIDC action. The application
must reject browser cookies on MCP routes and validate token resource, Origin,
issuer, audience, scopes, and revocation according to the canonical contract.

Offline checks use the exact prepared Terraform, provider, TFLint, and scanner
cache from `dev/toolchain.lock.json`. Run `make infra-check`; it never selects a
backend or applies a plan. Live validation inputs and owners are tracked in the
DR/LV runbooks under `docs/operations/`.

## Account cost budgets

Account-wide gross and cash-cost budgets are enabled by default. Set
`account_cost_budget_alert_email` to create two monthly budgets with actual-spend
alerts at 50%, 80%, and 100%; planning fails when the email is missing. Set
`enable_account_cost_budgets = false` only when the account owner has an
alternative alerting control. The gross-cost budget has no service filter and excludes
credits and refunds (`include_credit = false`, `include_refund = false`). The
cash-cost alert includes credits and refunds, so it tracks the credit-adjusted
bill estimate. Set the gross and cash thresholds with
`account_gross_cost_budget_usd` and `account_cash_cost_alert_budget_usd`.
AWS Budgets supports these cost-type switches ([AWS CostTypes API](https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_budgets_CostTypes.html),
checked 2026-10-07). Budget data updates several times per day, so alerts are
not real-time spend controls ([AWS Budgets guide](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html),
checked 2026-10-07).

The optional `enable_bedrock_spend_budget` action attaches an IAM deny policy
for `bedrock:InvokeModel` and `bedrock:CountTokens` to the application role at
the gross-budget threshold. Enable it only after the billing console confirms
the actual Anthropic Claude charge line is included in this account-wide
budget; Bedrock model-provider charges can appear under the provider's billing
line. The application daily token ledger remains the primary control. Its
allowance uses token-equivalent units, not dollars; a zero-token guardrail block
consumes the full bounded reservation and is not a financial cap.
