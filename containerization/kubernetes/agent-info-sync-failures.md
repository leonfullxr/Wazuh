# Agent-info sync failures: agents active on a worker, disconnected on the master

**Applies to:** Wazuh manager 4.14.x clustered on Kubernetes / OpenShift, with PVC-backed `/var/ossec/queue`

[Back to Kubernetes README](./README.md)

Agents report to their worker as expected. The dashboard and the master API list those same agents as `disconnected`. Restarting the affected worker pod clears it briefly, then the pattern returns.

This runbook walks the failure chain behind that pattern. The worker-local `wazuh-db` accepts HTTP requests but does not answer them, so `Agent-info sync` never pushes worker agent state to the master.

Both confirmed root causes are container-specific. One is easy to miss: analysisd sizes its thread pools from the CPU count visible inside the pod, not from the cgroup CPU quota. On a large node that produces thousands of threads, and those threads starve `wazuh-db`.

## Table of Contents

- [The symptom](#the-symptom)
- [Step 1: Confirm the fault is agent-info sync, not cluster transport](#step-1-confirm-the-fault-is-agent-info-sync-not-cluster-transport)
- [Step 2: Query the worker wazuh-db HTTP socket](#step-2-query-the-worker-wazuh-db-http-socket)
- [Step 3: Compare the worker and master agent state](#step-3-compare-the-worker-and-master-agent-state)
- [Root cause 1: analysisd thread pools use the node CPU count](#root-cause-1-analysisd-thread-pools-use-the-node-cpu-count)
- [Root cause 2: storage latency on the wazuh-db paths](#root-cause-2-storage-latency-on-the-wazuh-db-paths)
- [wazuh-db does not recover after an I/O stall](#wazuh-db-does-not-recover-after-an-io-stall)
- [Health probes for manager pods](#health-probes-for-manager-pods)
- [Do not delete the SQLite WAL and SHM files](#do-not-delete-the-sqlite-wal-and-shm-files)
- [Related](#related)

## The symptom

On the affected worker, each sync cycle writes two errors in `cluster.log`:

```text
ERROR: [Worker worker01] [Agent-info sync] Could not obtain data from wazuh-db: Error 2013 - Error sending HTTP request
ERROR: [Worker worker01] [Agent-info sync] Error synchronizing agent info: Error 2017 - Could not retrieve agents synchronization information from wazuh-db
```

Cluster transport in the same log still looks healthy:

```text
INFO: [Worker worker01] [Keep Alive] Successful response from master: keepalive
INFO: [Worker worker01] [Integrity check] Finished in 0.011s. Sync not required.
```

Other signatures show up in the same failure window:

| Where | Signature |
|---|---|
| Worker `ossec.log` | `:router: ERROR: database is locked on endpoint: /v1/agents/sync` |
| Worker `ossec.log` | `wazuh-db: WARNING: After vacuum, the database '0NN' has become just as fragmented or worse` |
| Master `ossec.log` | `wazuh-db: ERROR: Cannot set connection_status for agent <ID>` (repeats every 20 s) |
| Dashboard | `Could not get agents info` / `ERR_BAD_REQUEST - Invalid wazuh-db HTTP request` (HTTP 500) |

The pod stays `Running`. `wazuh-control status` lists every daemon as running. Kubernetes therefore sees nothing wrong.

## Step 1: Confirm the fault is agent-info sync, not cluster transport

```bash
kubectl exec -n <namespace> wazuh-manager-master-0 -- /var/ossec/bin/cluster_control -i more
```

Each subsystem tells a different story:

- `Last keep Alive` is recent and `Integrity check` finishes. Transport and file sync are fine.
- `Agents-info` shows `Last synchronization: n/a` and `Number of synchronized chunks: 0`. Only the agent-state path is broken.

If keepalive or the integrity check also fail, you are looking at a different problem. See [cluster debugging](./cluster-debugging.md) and the namespace and DNS section in that guide.

## Step 2: Query the worker wazuh-db HTTP socket

`Agent-info sync` reads worker-local agent state over an HTTP API on a Unix socket. Hit that socket on a failed worker, then hit it on the master and compare.

```bash
kubectl exec -n <namespace> wazuh-manager-worker-0 -- sh -lc \
  'timeout 10 curl --unix-socket /var/ossec/queue/sockets/wdb-http.sock -sv http://localhost/v1/agents/ids'
```

| Node | `GET /v1/agents/ids` | Interpretation |
|---|---|---|
| Correct | `HTTP/1.1 200 OK` with a JSON array of agent IDs | wazuh-db answers normally |
| Failed | `Empty reply from server` (curl exit 52), or no answer before the timeout | The socket accepts and reads the request, then writes no answer |

The socket still accepts connections. During the request, `/proc/net/unix` shows an extra connected entry for `wdb-http.sock`. A missing listener is a different failure. Here the socket takes the request and sends nothing back. On the master, `GET /` returns `404`. On the worker the same request never finishes. The fault hits every route, not a single endpoint.

> **Early indicator.** Long-lived Unix sockets between `wazuh-analysisd` and `queue/db/wdb` climb before the HTTP path fails. A healthy worker stays near 200. A worker heading for failure crosses 1000 in roughly 20 minutes.
>
> ```bash
> kubectl exec -n <namespace> wazuh-manager-worker-0 -- sh -lc \
>   'lsof -p "$(pgrep -x wazuh-analysisd)" -U 2>/dev/null | grep -c "queue/db/wdb"'
> ```

## Step 3: Compare the worker and master agent state

Confirm the agents are connected and only propagation is broken. The manager image has no `sqlite3` binary, so use the Python interpreter shipped in the image:

```bash
kubectl exec -n <namespace> <POD> -- /var/ossec/framework/python/bin/python3 -c "
import sqlite3
c = sqlite3.connect('/var/ossec/queue/db/global.db')
for r in c.execute('select id,name,last_keepalive,connection_status,sync_status from agent where id in (20,21,22)'):
    print(r)"
```

The two nodes disagree clearly. On the worker, agents are `active`, `last_keepalive` is current, and sync status is `syncreq_keepalive`. On the master, those same agents are `disconnected`, and their `last_keepalive` froze at the moment sync failed.

Workers also hold the full set of per-agent databases (`015.db`, `020.db`, and so on). The master only has `000.db` and `global.db`. That is expected: workers own local agent state, and the master only learns it through sync.

## Root cause 1: analysisd thread pools use the node CPU count

Check this root cause first. Wazuh logs do not surface it.

`analysisd.*_threads` defaults to `0`, which means automatic sizing. Analysisd then sizes each pool from the CPU set visible inside the container. On a large bare-metal node that is the full node CPU count, not the pod's cgroup quota. These commands show the gap:

```bash
kubectl exec -n <namespace> wazuh-manager-worker-0 -- sh -lc '
  echo "nproc:   $(nproc)"
  echo "cpu.max: $(cat /sys/fs/cgroup/cpu.max)"
  echo "threads: $(ps -o nlwp= -p "$(pgrep -x wazuh-analysisd)")"'
```

One worker showed `nproc: 336` with `cpu.max: 800000 100000` (8 cores per 100 ms period). Analysisd ran about 3,000 threads. CFS run-queue contention then delayed the local wazuh-db HTTP request until it timed out. A comparable cluster on a 16-CPU node used the same 8-core quota, ran about 158 threads, and did not fail.

> **`nr_throttled` does not catch this.** Both the failed and healthy clusters showed `nr_throttled: 0` and `throttled_usec: 0` in `cpu.stat`. The problem is scheduler contention among thousands of runnable threads, not quota throttling. Count threads. Ignore the throttling counters for this diagnosis.

Fix it by setting each pool explicitly in `/var/ossec/etc/local_internal_options.conf`:

```ini
analysisd.event_threads=4
analysisd.syscheck_threads=4
analysisd.syscollector_threads=4
analysisd.rootcheck_threads=4
analysisd.sca_threads=4
analysisd.hostinfo_threads=4
analysisd.winevt_threads=4
analysisd.rule_matching_threads=4
analysisd.dbsync_threads=4
```

Restart the StatefulSet so the change takes effect. With an 8-vCPU limit, thread count drops from about 3,000 to about 50. The wdb HTTP endpoint then answers in under one millisecond; before the change the same request timed out at 5 s.

Pick the value from the **cgroup CPU limit**, not from `nproc`. Half the vCPU limit is a reasonable start. Raise it only if you see `events_dropped`. Usual guidance keeps thread counts at or below the CPU thread count; see [analysisd tuning](../../troubleshooting/server/analysisd.md#tuning-analysisd-queues-and-threads). Inside a container, "CPU thread count" means the cgroup limit. Never leave the value at `0` on a large node.

## Root cause 2: storage latency on the wazuh-db paths

`wazuh-db` is SQLite-backed. Cluster synchronization depends on it. Latency on the volumes behind `/var/ossec/queue/db` and `/var/ossec/var/db` therefore produces `Agent-info sync` timeouts. Network block storage such as Ceph RBD is the usual culprit.

Requirements, measurement steps, `wazuh_db` tunables, and Ceph RBD guidance live in [wazuh-db storage latency](../../troubleshooting/server/wazuh-db-storage-latency.md). Two checks are enough to include or rule out storage here:

```bash
# A thread in the D state is blocked in an uninterruptible kernel I/O wait
kubectl exec -n <namespace> wazuh-manager-worker-0 -- sh -lc \
  "ps -eLo pid,stat,comm | grep wazuh-db | grep ' D '"

# Device-side latency behind the database paths
kubectl exec -n <namespace> wazuh-manager-worker-0 -- iostat -x 5 3
```

For scale: one investigated pair measured p50 0.020 ms and p99 0.088 ms on the healthy cluster, versus p50 1.48 ms, p99 3.79 ms, and a max of 52.6 ms on the failed cluster.

> **Do not stop at storage latency.** In the investigated case, `wazuh_db` tuning and NVMe-backed storage on both database paths did not stop the disconnections. Latency was real but secondary. Disconnections stopped only after the [analysisd thread-pool change](#root-cause-1-analysisd-thread-pools-use-the-node-cpu-count). Count threads before you plan a storage migration.

## wazuh-db does not recover after an I/O stall

This is expected architecture, not a bug. `wazuh-db` runs a worker pool against SQLite in WAL mode. Under a severe I/O stall those threads block in uninterruptible kernel syscalls, which protects data integrity. The process therefore cannot apply its own timeout and restart itself.

The main process stays up. A liveness probe that only checks process state still looks healthy. Once a worker enters this condition it stays there after the original storage problem ends. Recovery means restarting `wazuh-db` or the pod. Wazuh 5.x keeps the same architectural sensitivity, so upgrading does not fix a latency-bound environment.

Full mechanism, detection commands, and storage requirements: [wazuh-db storage latency](../../troubleshooting/server/wazuh-db-storage-latency.md#how-wazuh-db-behaves-under-io-stress).

## Health probes for manager pods

The `wazuh-kubernetes` manifests ship no liveness or readiness probe, and Wazuh publishes no official definition of a correct manager health test. Kubernetes also cannot detect the stalled socket on its own. A probe helps, but keep the cost low.

- **Recommended: TCP socket probes.** Use port `55000` (API) or `1515` on the master; use port `1514` on the workers. These start no process and add no socket load.
- **Do not use an exec probe that starts an interpreter.** A `python3` command that opens `/var/ossec/queue/db/wdb` every 30 s adds CPU and socket churn and worsens contention.
- **To probe wazuh-db directly**, use a native client and a long period. The standard manager image does not include `socat`, so this needs a custom image:

  ```yaml
  livenessProbe:
    exec:
      command:
      - /bin/sh
      - -c
      - 'echo "{\"command\":\"getstats\"}" | timeout 5 socat - UNIX-CONNECT:/var/ossec/queue/db/wdb | grep -q "\"error\":0"'
    initialDelaySeconds: 30
    periodSeconds: 60
    timeoutSeconds: 10
    failureThreshold: 3
  ```

  A shorter variant checks that the socket exists and answers one query:

  ```bash
  test -S /var/ossec/queue/db/wdb && \
    timeout 2 echo 'global get-agent-info 000' | socat - UNIX-CONNECT:/var/ossec/queue/db/wdb | grep -q 'ok'
  ```

  `test -S` alone is not enough. The socket file still exists during the stall. Only a query shows that it sends no answer.

## Do not delete the SQLite WAL and SHM files

An `initContainer` that deletes wazuh-db runtime files before startup looks like a clever mitigation:

```yaml
# Do NOT do this
command: ["sh", "-c", "rm -f /var/ossec/queue/db/wdb /var/ossec/queue/db/wdb.lock /var/ossec/queue/db/*.db-wal /var/ossec/queue/db/*.db-shm"]
```

Do not use it. Service comes back briefly, then data corrupts. The `.db-wal` file holds writes that are committed but not yet checkpointed (agent events, FIM data, syscollector data). The `.db-shm` file coordinates access between processes.

Deleting these files while transactions are pending leads to three outcomes:

- The database index becomes permanently corrupt.
- Uncommitted data is lost permanently.
- The same cluster-sync failure returns that the mitigation was meant to fix.

Only delete these files when `wazuh-db` is fully stopped and the OS has released all locks.

## Related

- [Cluster debugging](./cluster-debugging.md) - pod, DNS, namespace, and OOMKilled diagnostics for the same deployment
- [Wazuh on Red Hat OpenShift / OKD](./openshift.md) - SCCs, the s6-overlay UID blocker, and the indexer `vm.max_map_count` init container
- [Persistent storage](./persistent-storage.md) - what a pod restart keeps, and what the image creates again
- [wazuh-db storage latency](../../troubleshooting/server/wazuh-db-storage-latency.md) - storage requirements, D-state detection, `wazuh_db` tunables, and Ceph RBD guidance
- [Analysisd, EPS, and dropped events](../../troubleshooting/server/analysisd.md) - queue and thread tuning when throughput, not scheduling, is the constraint
- [Agent disconnections](../../troubleshooting/agents/disconnections.md) - agent-side causes, for an agent that truly sends no data
- [wazuh/wazuh#31841](https://github.com/wazuh/wazuh/issues/31841) - public issue for the same Error 2013, 2017, and 2012 family
