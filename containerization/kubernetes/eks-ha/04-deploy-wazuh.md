# 4. Deploy Wazuh

This path uses upstream [wazuh/wazuh-kubernetes](https://github.com/wazuh/wazuh-kubernetes)
Kustomize plus the overlay shipped here. Comments in each overlay file cover
what changed and why; below is only the order of operations.

If Helm fits better, the [chart in this repository](../helm/wazuh/) targets the
same topology and absorbs most of these overlay choices as defaults. Kustomize
here tracks Wazuh's own documentation more closely.

## 4.1 Clone the upstream repository

Pin a tag. `main` tracks 5.x alphas, which is a different deployment shape.

```bash
git clone --branch v4.14.7 --depth 1 https://github.com/wazuh/wazuh-kubernetes.git
cd wazuh-kubernetes
```

## 4.2 Generate certificates

The base needs certificate files on disk before `kustomize` builds, because a
`secretGenerator` turns them into Secrets. Two scripts, both plain openssl:

```bash
(cd wazuh/certs/indexer_cluster && bash generate_certs.sh)
(cd wazuh/certs/dashboard_http  && bash generate_certs.sh)
```

Output: `root-ca.pem`, plus `node`, `admin`, `dashboard` and `filebeat` key
pairs for the indexer cluster, and a self-signed pair for the dashboard HTTPS
listener.

Know two properties of these certs. They have no `subjectAltName`, which is why
the shipped config turns off hostname verification; SAN certs from
`wazuh-certs-tool.sh` let you re-enable it. Subjects are also hard-wired in
`opensearch.yml` under `plugins.security.authcz.admin_dn` and
`plugins.security.nodes_dn`, so any subject change must update those lists.
That mismatch is the usual reason an indexer never forms a cluster, and the
logs rarely look like a cert problem.

Retain the files. They are outside version control, generation is not
idempotent, and loss means reissuing TLS for the whole cluster.

## 4.3 Replace the default credentials

The base includes working plaintext passwords. Rotate all five before any
apply:

```bash
grep -rl 'to_be_replaced\|SecretPassword\|MyS3cr37P450r' wazuh/secrets/
```

| File | What it is |
|------|-----------|
| `indexer-cred-secret.yaml` | indexer admin, defaults to `admin` / `SecretPassword` |
| `dashboard-cred-secret.yaml` | dashboard service account, defaults to `kibanaserver` / `kibanaserver` |
| `wazuh-api-cred-secret.yaml` | Wazuh API user, defaults to `wazuh-wui` / `MyS3cr37P450r.*-` |
| `wazuh-authd-pass-secret.yaml` | agent enrollment password |
| `wazuh-cluster-key-secret.yaml` | manager cluster key, must be 32 characters |

Manifest values are base64:

```bash
printf '%s' "$(openssl rand -base64 24)" | base64 -w0
printf '%s' "$(openssl rand -hex 16)"    | base64 -w0   # cluster key, 32 chars
```

An indexer password change also requires a new bcrypt hash in
`wazuh/indexer_stack/wazuh-indexer/indexer_conf/internal_users.yml`. That file
is the bootstrap user database; hash and plaintext must match:

```bash
docker run --rm -it --entrypoint bash wazuh/wazuh-indexer:4.14.7 \
  -c 'JAVA_HOME=/usr/share/wazuh-indexer/jdk \
      bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh'
```

Do the rotate before first boot. `internal_users.yml` is read only while an
empty cluster bootstraps; after that the user store is the
`.opendistro_security` index and file edits do nothing. Post-bootstrap password
changes use `securityadmin.sh` as described in
[8. Operations](08-operations.md).

Also remove unused demo accounts (`kibanaro`, `logstash`, `readall`,
`snapshotrestore`). Their bcrypt hashes are in OpenSearch source, so they are
effectively public credentials.

## 4.4 Add the overlay

Copy [`manifests/overlay/`](manifests/overlay/) from this directory into the
clone as `envs/eks-ha/`:

```bash
cp -r /path/to/this/repo/containerization/kubernetes/eks-ha/manifests/overlay envs/eks-ha
```

Edit two places:

- `envs/eks-ha/ingress-dashboard.yaml`: hostname, plus the ACM certificate ARN
  annotation.
- `envs/eks-ha/indexer_conf/opensearch.yml`: only if certificate subjects
  changed in 4.2.

Render before apply and inspect the output:

```bash
kubectl kustomize envs/eks-ha | less
```

Skip this and you can miss silent no-ops. A Kustomize strategic-merge patch
that fails to match its target does nothing, so a clean apply is not proof the
patches landed. Check the fields that matter:

```bash
kubectl kustomize envs/eks-ha | grep -E 'replicas:|storageClassName:|provisioner:'
kubectl kustomize envs/eks-ha | grep -A8 'name: wazuh-workers'
```

Expect indexer `replicas: 3`, both managers at 1, `provisioner: ebs.csi.aws.com`,
and no `aws-load-balancer-internal: 0.0.0.0/0` anywhere. That annotation ships
in the upstream base on the `wazuh-workers` service and means internet-facing,
not internal, despite the name. The overlay clears it with an explicit `null`;
a plain merge patch would leave it, fighting the adjacent `scheme: internal`
annotation and exposing agent event ingestion to the internet.

## 4.5 Apply

```bash
kubectl apply -k envs/eks-ha/
```

Kustomize does not order resources for you. Manager and dashboard pods often
restart a few times while the indexer forms its cluster. On a fresh install
that is expected and usually settles within a few minutes.

Watch progress:

```bash
kubectl -n wazuh get pods -o wide -w
```

## 4.6 Verify

Check placement first; the design depends on it:

```bash
kubectl -n wazuh get pods -o custom-columns=\
'NAME:.metadata.name,NODE:.spec.nodeName,ZONE:.metadata.labels.topology\.kubernetes\.io/zone' 2>/dev/null
# clearer:
for p in $(kubectl -n wazuh get pods -o name); do
  node=$(kubectl -n wazuh get "$p" -o jsonpath='{.spec.nodeName}')
  zone=$(kubectl get node "$node" -o jsonpath='{.metadata.labels.topology\.kubernetes\.io/zone}')
  printf '%-40s %s\n' "${p#pod/}" "$zone"
done
```

Three indexers in three different zones, and the two managers in two different
zones. Shared zones for two indexers means `topologySpreadConstraints` did not
apply; return to 4.4.

Then exercise the Wazuh cluster:

```bash
# Manager cluster: one master, one worker, both connected
kubectl -n wazuh exec wazuh-manager-master-0 -- /var/ossec/bin/cluster_control -l

# Indexer cluster: 3 nodes, quorum formed
kubectl -n wazuh exec wazuh-indexer-0 -- \
  curl -sk -u admin:YOUR_PASSWORD https://localhost:9200/_cluster/health?pretty

# Alerts actually arriving
kubectl -n wazuh exec wazuh-indexer-0 -- \
  curl -sk -u admin:YOUR_PASSWORD 'https://localhost:9200/_cat/indices/wazuh-alerts-*?v'
```

Target indexer state is `status: green` with `number_of_nodes: 3`. Yellow on a
fresh install often only means the alerts index has no replica yet because no
data arrived; [5. Indexer HA](05-indexer-ha.md) covers setting replica count on
purpose.

## 4.7 Volumes

```bash
kubectl -n wazuh get pvc
kubectl get pv -o custom-columns=\
'NAME:.metadata.name,CLAIM:.spec.claimRef.name,ZONE:.spec.nodeAffinity.required.nodeSelectorTerms[0].matchExpressions[0].values[0]'
```

Each PV should list the zone of the claiming pod. That zone stays fixed for the
volume lifetime, which is why AZ loss strands a manager instead of moving it.
Record the master's volume zone; you will need it in
[7. Failure drills](07-failure-drills.md).

Next: [5. Indexer high availability](05-indexer-ha.md).
