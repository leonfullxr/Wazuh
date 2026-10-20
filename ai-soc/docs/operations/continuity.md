# Disaster recovery and live validation runbook

This runbook is an operator procedure for a later authorized synthetic deployment.
It contains no account values or credentials. A local unit, Compose or fixture result
does not complete a live gate. Record each live check in a timestamped evidence
artifact with the exact service SHA, content SHA, image digest and input manifest
SHA-256. Keep customer telemetry out of the staging corpus and ordinary logs.

## Before a live window

The platform, identity, Wazuh, network, AI platform, content, privacy and SOC
operations owners must supply their values through the
protected deployment manifest and acknowledge ownership. For every input record the
owner role, supplied/unavailable state, validation date and a nonsecret reference.
Never put secret values in this runbook, a fixture, Terraform output, test report or
ticket.

Check these groups before scheduling the window:

1. Private AWS account/region, two or more private AZ subnets, internal ALB, task and
   execution roles, endpoint policies, encrypted state backend and immutable ECR
   digests.
2. Browser IdP issuer/client/groups claim, ALB signer/certificate, MCP issuer/JWKS,
   resource audience, scopes and finite Origin allowlist. Browser ALB authentication
   and MCP bearer authentication are separate.
3. Each synthetic Wazuh site's version, mapping, analyst-only roles, DLS policy hash,
   JWT audience/issuer, pinned CA secret version/hash, private route/DNS, read
   permissions, PIT and stable sort support.
4. KMS signing key IDs and verifier overlap, CSRF/cursor/feedback key versions,
   DDB table and stage-admission settings, encrypted audit/feedback queues and DLQs.
5. Bedrock model/profile, numbered guardrail, allowed effort and context/count
   strategy, source VPC endpoint, logging destination and optional embedding state.
   Unsupported embedding or prompt-cache capability remains explicitly disabled.
6. Approved content commit, detached approval reference, public docs manifest,
   synthetic golden corpus and reviewed baseline; validate their hashes before use.
7. Synthetic CI OIDC role, protected `synthetic-staging` environment, nightly schedule,
   on-call/alarm destinations, log access and retention/deletion ownership.

Missing required inputs means `NOT_CONFIGURED`; an attempted check with unavailable
connectivity or dependency means `NOT_RUN` with the blocking input named. Neither is a
pass. Do not infer that an empty dashboard, empty queue, absent metric or missing
nightly artifact means zero errors.

## Recovery procedures

### Service or Availability Zone loss

1. Confirm `/health/live` and `/health/ready` separately. Readiness must fail closed if
   required state, identity, audit or configuration is unavailable.
2. Check ALB target health, private task count and endpoint health. Preserve the
   minimum of two healthy Fargate tasks; task ingress is only from the internal ALB
   security group.
3. Drain old tasks within the 120-second request deadline and 160-second target drain
   grace. Keep the 150-second ALB idle timeout. Do not force-migrate a stale plan,
   completion, audit acknowledgment or lease to a new process.
4. Verify a new authenticated read-only synthetic question, audit acknowledgment,
   bootstrap/CSRF, MCP protected-resource metadata and official-client tool call.
   Do not enable the service until the identity and site checks below pass.

### State, admission, or ambiguous SDK outcome

1. Stop issuing test load; preserve the exact failed request IDs only in the protected
   evidence system. Ordinary logs contain no question, row, token or prompt.
2. Read the operation/completion record strongly and inspect service/site slot fences,
   recovery-ring status, budget reserve/settle state and audit acknowledgment. Do not
   repeat a provider call while its physical attempt or ambiguous outcome remains
   unresolved.
3. A cancelled waiter does not release a slot while the physical call remains active.
   Recovery may reclaim only after the typed hard deadline plus 35 seconds and a
   fenced conditional update. Expired DDB TTL alone is not proof that a record is
   absent.
4. Resume only after two-instance SDK request-shape and race checks pass, including
   concurrent service/site maxima and no duplicate charge/completion. Escalate any
   unresolved ambiguous commit to the state owner; never delete state to clear an
   alarm.

### Audit queue lag, archive error or DLQ arrival

1. Treat `AuditQueueAge` over 120 seconds for two one-minute periods as breaching;
   missing age data also breaches. A visible `AuditDlqNotEmpty` message alarms
   immediately. Do not interpret no metric or an empty dashboard as zero backlog.
2. Verify consumer task health/role, queue receive/delete and KMS decrypt, archive
   bucket `PutObject` and data-key permissions. Inspect only aggregate received,
   archived and failed counters in ordinary logs.
3. Restore archive delivery before redrive. The consumer writes the canonical event
   with conditional create before deleting the queue message. Only HTTP 412
   `PreconditionFailed` confirms an existing object and is an idempotent success;
   HTTP 409 `ConditionalRequestConflict` and other write failures leave the message
   for retry and eventual DLQ redrive.
4. Review a DLQ event only through the approved encrypted audit path. Never copy its
   body into a ticket or general-purpose log. Confirm queue retention (7 days), DLQ
   retention (14 days), encrypted/versioned archive and at least 90-day archive
   retention after recovery.

### Identity, site CA or private-path failure

1. Deny the affected site and preserve the synthetic test result. Do not fall back to
   a standing indexer reader, system CA bundle, redirect, proxy or public indexer.
2. The identity owner verifies ALB assertion signer, issuer, client, expiry, groups,
   revocation objective (15 minutes), and that tasks can reach the documented
   regional ALB public-key URL through exact host routes or a configured proxy
   allowlist (see infra README). Security groups enforce IP and port only; they do
   not prove the key hostname or URL path. The MCP owner separately verifies bearer resource, issuer,
   audience, scope, Origin and token type.
3. The site/Wazuh and network owners verify the exact role/DLS attestation, CA secret
   version/hash, hostname, private DNS, route and indexer version. A missing or wrong
   CA pin remains unreachable; unknown visibility never becomes a qualified empty
   result.
4. Rotate per-site signing keys only after the Wazuh owner installs the new public
   verifier. Verify both keys during the approved overlap, then remove the old key
   and record the new key/config hashes. A changed policy or CA anchor invalidates
   continuation state and requires a fresh question.

### End a qualification session and verify inventory

Use this procedure after each hourly session. It removes session networking and
compute while retaining keys, state, evidence, archive queues, logs, and spend
controls. Production defaults remain `enable_session_resources = true`.

1. Stop generating test traffic and export/hash the session evidence. Disable
   new archive launches while the network still exists by applying
   `enable_audit_archive_schedule = false` with session resources enabled. Plan,
   inspect, and apply this change with the active qualification variables:

   ```text
   terraform -chdir=infra plan -var-file=qualification.tfvars \
     -var=enable_session_resources=true -var=enable_audit_archive_schedule=false \
     -out=../build/archive-stop.tfplan
   terraform -chdir=infra show ../build/archive-stop.tfplan
   terraform -chdir=infra apply ../build/archive-stop.tfplan
   ```

   Then
   run `make check-session-teardown-preflight`. It verifies the schedule is
   disabled and no archive tasks are running. If a task is
   running, wait for it or stop it with `aws ecs stop-task`, then repeat the
   check. The check polls task `lastStatus` until every archive task is
   `STOPPED`, then verifies that its task ENI has been deleted before it passes.
2. Drain audit and feedback messages to the encrypted S3 archive before
   teardown. Manually start the `audit-archive` ECS task from the retained
   cluster using the same private subnets and task security group as the
   scheduled task. Use the task inputs exported by Terraform:

   ```text
   archive_config=$(terraform -chdir=infra output -json archive_task_run_configuration)
   cluster=$(jq -r .cluster_name <<<"$archive_config")
   task_definition=$(jq -r .task_definition_arn <<<"$archive_config")
   subnets=$(jq -r '.subnet_ids | join(",")' <<<"$archive_config")
   security_group=$(jq -r .security_group_id <<<"$archive_config")
   aws ecs run-task --cluster "$cluster" --task-definition "$task_definition" \
     --launch-type FARGATE \
     --network-configuration "awsvpcConfiguration={subnets=[$subnets],securityGroups=[$security_group],assignPublicIp=DISABLED}"
   ```

   This uses Fargate `awsvpc` networking with private subnets and no public IP
   ([ECS `AwsVpcConfiguration`](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_AwsVpcConfiguration.html)).

   One invocation archives up to ten messages from each queue. Repeat `RunTask`
   until queue depths are zero; inspect the archive objects and task exit status
   after each run. Never delete queue messages to make the inventory look clean.
   Run `make check-session-teardown-drained` and continue only when all four
   retained queues have zero visible, in-flight, and delayed messages. SQS
   counts are approximate and may take at least one minute to converge after
   sends stop; wait and repeat the check before proceeding
   ([SQS `GetQueueAttributes`](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_GetQueueAttributes.html)).
3. Keep the same encrypted remote backend and protected variable files used for
   apply. Create and inspect a saved plan with the session switch off:

   ```text
   terraform -chdir=infra plan -var-file=qualification.tfvars \
     -var=enable_session_resources=false -out=../build/session-teardown.tfplan
   terraform -chdir=infra show ../build/session-teardown.tfplan
   terraform -chdir=infra apply ../build/session-teardown.tfplan
   ```

   The plan should remove interface and gateway endpoints, ALB/listeners,
   application tasks/service, session task policy, and disabled archive
   schedule/task.
   It must retain the KMS keys, DynamoDB tables, buckets, queues, log groups,
   CloudTrail/invocation logging, account budgets, and alarm configuration.
   The application role loses its endpoint-bound session policy while the
   Bedrock endpoint is absent. If any retained resource is planned for deletion,
   stop and investigate before applying.
4. Run `make check-session-teardown` with the same initialized backend. It fails
   if Terraform state still contains a session resource, a deployment-derived
   foundation resource is missing, any audit/feedback/DLQ queue is non-empty, or
   an archive task has not reached `STOPPED` and its task ENI has not been
   deleted. Its expected foundation inventory comes
   from the current `sites` map, optional logging settings, and budget settings;
   disabling account budgets is accepted only when the account owner records
   the documented alternative alerting control.
5. Check external lab inventory separately: terminate session-only lab hosts;
   remove their ENIs, attached temporary volumes, public IPv4 addresses, and
   temporary proxy resources. Keep shared SNS topics, retained Secrets Manager
   secrets, the domain, ACM certificates, and identity configuration for the
   next session. Record each external resource ID and its retained/deleted
   disposition in the evidence artifact.
6. To run again, set `enable_session_resources = true` and
   `enable_audit_archive_schedule = true`, inspect a fresh saved
   plan, and apply with the same backend and protected inputs.

### Separate full-destroy drill

This is a distinct, data-destructive exercise for a disposable qualification
account only. Production stacks must keep `qualification_profile = false` and
must not use the force-destroy protections intended for qualification.

1. Obtain the account owner's explicit approval for deleting the foundation.
   Export final evidence and archive every audit item that must be retained;
   confirm retention and deletion obligations with the data owner. Record the
   queue depths and all persistent resource IDs first.
2. Complete the session teardown procedure above. After approval, empty all
   retained versioned evidence, invocation, docs, and CloudTrail buckets,
   including noncurrent object versions, using the approved retention procedure.
   Then create a distinct destroy plan using the same backend and protected
   variables, and inspect it before applying:

   ```text
   terraform -chdir=infra plan -destroy -var-file=qualification.tfvars \
     -out=../build/full-destroy.tfplan
   terraform -chdir=infra show ../build/full-destroy.tfplan
   terraform -chdir=infra apply ../build/full-destroy.tfplan
   ```

   Review every key, secret reference, table, evidence/archive bucket, budget,
   log group and trail in the plan. Stop if any resource is shared or its data
   disposition is unclear.
3. If the optional Budgets deny action is enabled, verify the active policy is
   detached from the application role before deleting the account budget
   configuration. Cost data can lag; neither budget alerts nor the deny action
   provide a real-time spend cap. Check the actual Claude billing line before
   relying on that action.
4. Expect KMS keys to enter a pending-deletion window (30 days with the module
   default). Do not schedule key deletion until evidence and retention owners
   approve. Empty and delete the encrypted Terraform state bucket last, after
   the workload root and its dedicated data buckets are gone; that bucket is
   not managed by this module.
5. Reconcile the final AWS inventory and billing console after deletion. Record
   remaining externally managed resources, cancellation dates, and any delayed
   charges. A completed Terraform destroy alone is not proof of full deletion.

### Content or image release rollback

1. Stop promotion if service/content/image/docs hashes do not match the approved
   manifest, a required document anchor is absent, secret scan fails, or the runtime
   image digest differs from the expected immutable digest.
2. Restore the prior service image together with its exact content commit, pack,
   public-doc manifest and docs bytes. Never pair a new application with an old
   mutable document path or silently rebuild from a changed source tree.
3. Validate the previous digest and detached content approval; ask analysts to start
   a fresh question if policy, CA or content anchors changed. Do not migrate old
   cursors or follow-up plans across unreviewed content.
4. Record the rolled-back commit and reason in the protected release evidence. Resume
   promotion only after two clean linux/amd64 builds reproduce the same runtime OCI
   config and layer digests and the immutable pack/docs checks pass.

## Live validation gates

Run `make staging-golden` only from the protected synthetic-staging environment with
the authorized manifest and short-lived role. Pass `--clients-config` through
`STAGING_ARGS`; this is not part of `make ci-check`.
The protected file is `config/staging-validation.json` (never committed). An
illustrative non-authoritative example lives at
`examples/staging-validation.manifest.example.json`.

Manifest schema versions `1` and `2` are legacy placeholders and always record
`NOT_RUN`. Schema version `3` selects one registered gate, lists its applicable
`GP3`/`GP4` acceptance IDs, owner roles, artifact pins, an `expected_deployment`
binding, gate inputs and the operator command list. Secret material, PEM blocks and
raw tokens are rejected at validation. Inline results and manifest evidence refs are
never observations and cannot certify a gate.

Every adapter implements the frozen `GateAdapter` contract in
`scripts/staging/clients.py`: an adapter configuration registers its gate, contributor ID,
factory and strict Pydantic input model. The runner parses `inputs.adapter` with that model
(`extra="forbid"`) from `inputs.adapter.<contributor_id>`, then passes the typed model, an `AWSServiceClientFactory` from an
explicitly configured assumed-role session, and a `DeploymentBinding`. Several contributors
may register for one gate; their distinct obligation rows compose into one gate result.
Duplicate or unknown obligation IDs fail the gate. Each report includes its own binding.
The runner observes the deployment before and after evaluation and fails if those
observations or any report binding differ. A report returns typed `ObligationResult` rows
with `PASS`, `FAIL`, `NOT_RUN` or `NOT_CONFIGURED` and checkable evidence references.
References are typed as CloudTrail event IDs, Bedrock request IDs, S3 version IDs or
file SHA-256 values; a bare label cannot support a passing obligation.
Missing clients, observations, required obligations or evidence references remain
`NOT_RUN`. Adapters cannot construct results by copying expected pins. The registry in
`scripts/staging/registry.py` covers all eleven gates plus GP3 and GP4. This is the frozen
adapter interface for independent gate implementations.

Example adapter skeleton:

```python
from pydantic import BaseModel, ConfigDict
from scripts.staging.clients import AWSServiceClientFactory, GateAdapterReport
from scripts.staging.models import DeploymentBinding, GateId

class IdentityInputs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    issuer_ref: str
    client_ref: str

class IdentityAdapter:
    gate_id = GateId.LV_IDENTITY

    def evaluate(self, *, inputs: IdentityInputs, clients: AWSServiceClientFactory,
                 binding: DeploymentBinding) -> GateAdapterReport:
        # Observe live identity behavior and return evidence-backed obligations.
        ...
```

Register with `factory` and `input_model` `module:Symbol` names, a unique
`contributor_id`, and nonsecret constructor options. Put each contributor's fields in its own
`inputs.adapter.<contributor_id>` object. Different contributors can use strict input models
with different required fields without receiving each other's data.

The optional `nightly` and `network` entries in the clients config use the same
`{"factory": "module:Symbol", "options": {...}}` shape. The runner resolves each configured
factory and calls it as `factory(clients=explicit_service_client_factory, **options)`; the result
must implement `NightlyResultsClient` or `NetworkProbeClient`. These collector factories receive
the same explicitly assumed-role service-client factory as ordinary adapters. Missing factory
configuration leaves the corresponding collector absent, so the gate stays `NOT_RUN`.

Supply a separate nonsecret JSON file with an explicit non-default source profile,
assumed role ARN and expected account ID, region, ECS cluster/service and application
container, for example `examples/staging-clients.example.json`. The CLI assumes the
configured role from the named profile and verifies STS `GetCallerIdentity` account and
assumed-role ARN before creating service clients. Environment, container and instance
credential providers are rejected. Boto3 searches multiple providers, including container
and instance credentials, so the runner checks the resolved source-profile provider.
The observer reads the account from STS and cluster ARN, service ARN, primary deployment ID,
primary task-definition ARN, running task image digest and task environment from ECS. Every
sampled running task must have `startedBy` equal to the primary deployment ID. The observed
binding includes that ID, so reports, repeated observations and aggregation compare the full
deployment instance as well as cluster, service and task-definition ARNs. A manifest may pin
`expected_deployment.deployment_id`; when omitted, the runner still checks task membership and
requires the same observed ID across the complete qualification. The service
task exports `SOC_SERVICE_SHA`, `SOC_CONTENT_SHA`, `SOC_SERVICE_CONFIG_JSON` and
`SOC_CONFIGURATION_SHA256`; Terraform computes the last value as SHA-256 of the exact
canonical JSON string it exports in `SOC_SERVICE_CONFIG_JSON`. The observer verifies that
same string. Missing values or inconsistent running tasks yield no observation.
Network inputs accept one or more site records; every site must return all seven
evidence-backed obligations. GP3 independently requires separate passing stage and trace
obligations, each with its own typed evidence reference.
GP4 independently requires missing-pin denial, wrong-pin denial and rotation/hash
invalidation observations. AWS API references: [STS GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html),
[ECS DescribeTasks](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DescribeTasks.html),
[ECS Service](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_Service.html),
and [Boto3 credentials](https://docs.aws.amazon.com/boto3/latest/guide/credentials.html). ECS
deployment IDs and service task `startedBy` behavior: [ECS Deployment](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_Deployment.html)
and [ECS Task](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_Task.html).
Bedrock PrivateLink routing details:
[Bedrock VPC interface endpoints](https://docs.aws.amazon.com/bedrock/latest/userguide/vpc-interface-endpoints.html).

Each invocation writes a unique `build/evidence/live/<run-id>/<gate-id>.json` file;
reusing an output path is rejected. Use one explicit `--run-id` for gates from the
same qualification window. `scripts/staging_aggregate.py` consumes those files and
writes `lv1-summary.json`. It refuses duplicate rows or any disagreement in observed
account, region, deployment, image digest, service SHA, content SHA or configuration
hash. An LV-1 `PASS` requires all eleven gate rows and both acceptance rows to pass
with the same observed binding and evidence-backed obligations. Otherwise the summary
shows the validated subset and keeps LV-1 `NOT_RUN` or `FAIL`.

The evidence envelope keeps `schema_version`, `status`, `recorded_at`, `reason` and
`result`. A `LiveGateResult` records the typed gate ID, owners, manifest SHA-256,
service/content/artifact pins, observed binding, typed obligation results, acceptance
results, status, commands, structured results, typed checkable evidence refs and timestamp.
Its binding includes the cluster, service and active task-definition ARNs.
Secrets are redacted before serialization. An absent manifest sets `result` to null
and exits nonzero with `NOT_CONFIGURED`.

| Gate | Required result before activation |
|---|---|
| `LV-PLATFORM` | Internal ALB only; two private tasks; exact endpoint/resource policies; immutable image digest; rolling 150/160-second values; public invocation denied. |
| `LV-IDENTITY` | Signed ALB assertion validation, expiry/groups and revocation within 15 minutes; direct task ingress denied. |
| `LV-MCP` | Official client initialize/list/ask/page/feedback; wrong resource, issuer, scope, token type, browser cookie, version and Origin denied. `soc_ask`/`soc_page` structured output remains the frozen Answer/FetchResult; server instructions must treat row values as untrusted host-supplied data, not verified evidence. |
| `LV-SITE` | Per-site analyst read roles, forbidden write, hidden-row sentinel, 401/403 versus empty, coherent snapshot, stable pagination, JWT claims, key rotation and site isolation. |
| `LV-NETWORK` | Every configured site is reachable only over the private route with pinned CA/hostname; no redirect/proxy/system-CA fallback/public indexer; Bedrock invocation allowed through its VPCE and denied on the public path. GP4 separately tests missing pin denial, wrong pin denial and rotation/hash invalidation. All seven obligations require nonsecret evidence refs; missing or unobserved obligations stay `NOT_RUN`. |
| `LV-STATE` | Two-replica DDB transactions, consistency, stage admission, cancellation, crash/recovery, ambiguous outcome, fenced release and no double budget settlement. |
| `LV-MODEL` | Exact model/profile, guardrail and tool-free request; count/context/usage, timeout, failure and output validation; unsupported cache/embedding explicitly disabled. |
| `LV-CONTENT` | Detached approved source, immutable pack/docs/S3/CloudFront bytes and heading anchors; mismatch blocks promotion and rollback restores paired hashes. |
| `LV-OBSERVABILITY` | Audit SQS acknowledgment through encrypted S3 archive, DLQ/lag alarms, configured retention/access review, CloudTrail and invocation-log inventory; no raw prompt in standard telemetry. |
| `LV-NIGHTLY` | Full required golden denominator, 100% deterministic routing, candidate/drop denominator, empty/missing/failure distinctions, separate cost, latency, cache and scheduled missing-run observations. GP3 requires separately observed stage and trace evidence. |
| `LV-UI` | Authenticated deployed browser flows, CSRF, paging, continuation, feedback and cancellation; EN/ES, 320px, keyboard/screen reader; attach axe and manual findings separately. |

The nightly deterministic router must score 100% of all required planned cases; a
missing or skipped case counts as incorrect. A drop-rate alarm fires only when one
complete run has at least 20 syntactically valid candidates and its rate is strictly
greater than the reviewed baseline plus five percentage points. Equality does not
alarm. A zero-candidate run reports `empty_cohort=true` and a null rate; it is not
reported as 0% dropped. Keep `no_findings`, invalid JSON, provider failure, missing
case and missing run as separate results. At least 20 reviewed EN and 20 reviewed ES
judgment cases are required for a baseline. An enabled schedule with no run for two
hours is an operational alarm; an unavailable configuration is `NOT_CONFIGURED`,
not green.

Before production enablement, complete live qualification for the account, identity,
site network, KMS, model, content, observability, staging and CI configuration. Record
missing values as `NOT_CONFIGURED` and unexecuted checks as `NOT_RUN`.
