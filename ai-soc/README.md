# Wazuh AI SOC

Wazuh AI SOC is a read-only assistant for Wazuh analysts. It plans an analyst's question by topic, gathers bounded evidence from the Wazuh indexer for each topic, and returns a separate, cited judgment for each one. It does not change Wazuh configuration or perform active response.

It runs as a private HTTPS service on AWS (ECS Fargate behind an internal ALB), uses Amazon Bedrock for judgment with a pinned guardrail, and serves both a browser UI and an MCP endpoint (`soc_ask`, `soc_page`, `soc_feedback`).

## How it works

1. Routing cues map the question to reviewed topics. Questions that match no topic get a clarification or a refusal, never a guess.
2. Each topic runs a read-only playbook: allowlisted indexer queries, count and field checks, and recency checks, under the analyst's own indexer permissions.
3. The model selects findings only from reviewed templates, and every finding must cite evidence returned in step 2. An independent validator removes anything uncited or unsupported.
4. Every answer is audited to an encrypted queue before it is returned. If audit is unavailable, no answer is returned.

See [Architecture](docs/architecture.md) for the full request flow and how false positives and false all-clears are handled.

## Repository layout

| Path | Contents |
|---|---|
| `src/ai_soc` | Service: API, MCP, planning, query, judgment, validation, state, telemetry |
| `web/` | Browser UI (React and TypeScript, built into the image) |
| `ui/` | Legacy Playwright and axe runner dependencies retained during test-tool migration |
| `contracts/v1` | Generated wire schema, OpenAPI document and TypeScript types |
| `infra/` | Terraform for the AWS deployment, plus the reference egress proxy |
| `scripts/` | Image build, platform preparation, live qualification and teardown checks |
| `examples/content-seed` | A runnable synthetic content repository: topics, playbooks, templates, public docs |
| `config/` | Example service configuration and qualification IAM policies |
| `docs/` | Architecture, specification, contracts, source capabilities and runbooks |

## Requirements

- Linux x86_64, Git, GNU Make, CPython 3.12.13, [uv 0.11.28](https://docs.astral.sh/uv/), Docker Engine with BuildKit.
- bubblewrap at `/usr/bin/bwrap` with user and network namespaces (builds run with networking denied), `gcc`, `curl`, `unzip`, `tar`, `xz`, `sha256sum`.
- At least 2 GiB free on `/dev/shm` for image builds.
- For deployment: an AWS account with an existing VPC and private subnets, an ACM certificate, an OIDC identity provider, Bedrock model and guardrail access, and private network reachability to the Wazuh indexer.

## 1. Prepare the toolchain

```sh
make bootstrap
```

This installs the locked Python and browser dependencies and fetches the pinned Terraform, TFLint, Trivy, Node and base images listed in `dev/toolchain.lock.json`, verifying each digest. Everything after this step runs offline. The production browser build comes from `web/`; the isolated Playwright preparation continues to use the legacy runner lock until browser test tooling has its own lockfile.

## 2. Build the content pack

Topics, routing cues, playbooks, finding templates and public reference pages live in a separate content repository, built and signed with the `ai-soc-content` CLI. `examples/content-seed` is a complete synthetic example; copy it into its own Git repository and replace its content with reviewed content for your site. Its [README](examples/content-seed/README.md) walks through building and verifying a pack.

The playbook limits in the seed (for example the one-hour recency limit) are synthetic. Set real values from your site's ingestion behavior. [Source capabilities](docs/source-capabilities.md) lists what each Wazuh source can and cannot establish.

## 3. Build the service image

```sh
make image-reproducibility
```

This builds `web/`, then makes clean linux/amd64 OCI builds with `--network=none` and `--no-cache`, and checks that two independent builds of the same commit produce identical config and layer digests. The generated files are copied into `/service/ui/dist` inside the image so the existing service mount remains stable. The content pack is a provenance input recorded in image labels, not baked into the image. Evidence and the OCI archives are written under `build/evidence/image-repro/`. Push the verified image to a private ECR repository and deploy it by digest.

## 4. Deploy on AWS

Follow [infra/README.md](infra/README.md). In short:

1. Configure an encrypted remote Terraform state backend outside git, and keep `*.tfvars` outside git.
2. Supply the VPC, subnets, certificate, OIDC settings, indexer CIDRs and CA, Bedrock model and guardrail ARNs, image digest, content commit and alarm topic.
3. Validate offline with `make infra-check`, then plan and apply from your protected deployment system.
4. Probe Bedrock capability with the [model probe runbook](docs/operations/model-probe.md) before enabling a model.

The module creates no VPC, public subnet or NAT gateway. Session resources (ALB, tasks, endpoints) can be switched off between use windows while keys, state, audit storage and alarms remain; `make check-session-teardown` verifies the result.

## 5. Qualify the deployment

Offline checks do not prove a live site works. Before analysts rely on the service, run the live validation gates in the [continuity runbook](docs/operations/continuity.md): source mapping and field coverage, analyst document-level permissions, count and paging behavior, model and guardrail responses, budgets, and audit queue and archive recovery. `make staging-golden` runs the synthetic staging evaluation from the protected environment; `examples/staging-validation.manifest.example.json` shows the manifest shape. Any gate that cannot run stays `NOT_RUN` or `NOT_CONFIGURED` rather than passing.

## Operations

- [Disaster recovery and live validation runbook](docs/operations/continuity.md)
- [Telemetry and audit operations](docs/operations/telemetry.md)
- [Bedrock capability probe](docs/operations/model-probe.md)

## Analyst workspace

The workspace modules provide a PostgreSQL-backed analyst workflow used by the browser application. Run `make bootstrap`, then run `make web-build` to build it. The `make ws-*` targets manage the workspace database and processes. See the [workspace operations guide](docs/operations/workspace-m3.md) for setup.

The workspace is an opt-in development feature. Its commands and content assets currently require a source checkout. The AWS service image serves the `web/` build, but it does not configure the workspace database or worker processes. Workspace backend packaging and production deployment have not been qualified.

## Try it locally

You can run the service on loopback with synthetic data, identities and a deterministic stand-in model. It is a demonstration, not a quality signal, and it refuses live or cloud environment variables.

```sh
make fixture   # build a pack from the synthetic content seed
make dev       # serve REST and MCP on 127.0.0.1:8000 (PORT=8010 to change)
```

Credentials are written to `build/dev-fixture/credentials.json`. Call `GET /v1/bootstrap` with the ALB header from that file, then send the returned `__Host-soc-csrf` cookie and `csrf_token` (as `X-SOC-CSRF`) with `POST /v1/questions`, for example `{"question":"Investigate authentication review.","environment_id":"synthetic","timezone":"UTC","model_id":"synthetic-model"}`. The seed answers LDAP, authentication review and vulnerability review questions in English and Spanish. The browser UI needs an ALB in front of it, so it is not usable locally.

## Reference

- [Architecture](docs/architecture.md)
- [Domain glossary](CONTEXT.md)
- [Service specification](docs/specification.md)
- [Service and wire contracts](docs/contracts.md)
- [Source capabilities](docs/source-capabilities.md)

## License

MIT. See [LICENSE](LICENSE).
