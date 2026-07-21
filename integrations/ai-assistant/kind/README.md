# Track B - kind cluster and cross-tenant isolation

Move the **same** `auth-shim` and `tool-service` images from Compose into a
single-node [kind](https://kind.sigs.k8s.io/) cluster with two namespaces.
Wazuh and Ollama stay on the host Docker stack; pods reach them via the Docker
bridge gateway IP (`kind/host-gateway.sh`).

This proves what Compose cannot: **NetworkPolicy walls**, **per-tenant mint
keys**, and **tenant-claim rejection** (D30/D36).

## Prerequisites

- Docker Compose PoC already working (`make wazuh`, `make securityconfig`,
  `make poc`, `make ollama`, `make embed`, lane 0 enabled in `.env`)
- `make evals-fresh` green on Compose (baseline)
- ~4 GB RAM for kind on top of the Wazuh stack
- `envsubst` (gettext)

Install kind/kubectl locally (no root):

```bash
./kind/install-prereqs.sh
export PATH="$PWD/.bin:$PATH"
```

## Layout

| Where | What |
|-------|------|
| Host Docker | Wazuh indexer `:9200`, Ollama `:11434` |
| `tenant-a` namespace | auth-shim NodePort `:30771`, tool-service NodePort `:30880` |
| `tenant-b` namespace | auth-shim NodePort `:30772`, tool-service NodePort `:30881` |

**Key material**

- **tenant-a** uses `keys/` - the same keypair the indexer JWT domain trusts
  (golden evals must pass).
- **tenant-b** uses `keys/tenant-b/` - valid RSA mint key, but **not** trusted
  by the lab indexer. Tenant-b can pass service-level auth yet cannot read
  telemetry; per-tenant indexers are an AWS-stage concern.

**Identity**

- Both tenants verify `analyst1` against the host indexer via authinfo (V3.6).
- Each shim mints a turn JWT with `tenant` = `tenant-a` or `tenant-b` from its
  environment registry ConfigMap.

## Bring-up

```bash
export PATH="$PWD/.bin:$PATH"   # if using install-prereqs

make kind-up          # cluster + load images (kindnet enforces NetworkPolicy)
make kind-tenants     # keys, apply both tenants
make kind-isolation   # four assertions, exit 0 = pass
```

`make kind-down` deletes only the kind cluster; the Docker Wazuh/Ollama stack
is untouched.

## What each assertion proves

1. **Happy path** - tenant-a Basic auth → tenant-a shim → tenant-a tool-service
   returns a labeled answer (lane 0 OK).
2. **Cross-tenant token** - tenant-a turn JWT on tenant-b service → HTTP
   401/403 and `cross_tenant_token_rejected` in tenant-b audit logs.
3. **Cross-namespace network** - a curl pod in tenant-a cannot reach
   `tool-service.tenant-b.svc` (timeout/refused - the wall, not the guard).
4. **Golden set** - `run_evals.py` against tenant-a NodePorts passes 9/9
   (k8s move changed no behavior).

## Makefile targets

| Target | Action |
|--------|--------|
| `kind-up` | Create cluster, build & `kind load` images |
| `kind-keys` | Ensure `keys/` + generate `keys/tenant-b/` |
| `kind-tenants` | Deploy tenant-a and tenant-b |
| `kind-isolation` | Run `kind/isolation_suite.sh` |
| `kind-down` | `kind delete cluster` |

## Env knobs (golden / isolation)

| Variable | Default (tenant-a via kind) |
|----------|----------------------------|
| `WAI_EVAL_SHIM_URL` | `http://localhost:30771` |
| `WAI_EVAL_SVC_URL` | `http://localhost:30880` |
| `WAI_EVAL_ENV_ID` | `tenant-a` |

## Troubleshooting

- **Pods ImagePullBackOff** - run `make kind-up` again to reload local images.
- **401 on exchange** - re-run `make securityconfig` so `analyst1` exists on
  the indexer; confirm auth-shim can reach `https://<host-gw>:9200`.
- **Golden fails on tenant-a** - tenant-a must use `keys/` trusted by indexer;
  re-run `make securityconfig` if keys were rotated.
- **NetworkPolicy decorative** - confirm kindnet is up (`kubectl get pods -n kube-system -l app=kindnet`);
