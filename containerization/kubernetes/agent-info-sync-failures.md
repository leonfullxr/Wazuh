# Agent-info sync failures: agents active on a worker, disconnected on the master

**Applies to:** Wazuh manager 4.14.x clustered on Kubernetes / OpenShift, with PVC-backed `/var/ossec/queue`

[Back to Kubernetes README](./README.md)

The agents report to their worker correctly. The dashboard and the master API show the same agents as `disconnected`. A restart of the affected worker pod corrects the problem for a short time. The problem then occurs again.

This runbook explains the failure chain behind that pattern. The worker-local `wazuh-db` accepts HTTP requests but does not answer them. As a result, `Agent-info sync` never sends the worker agent state to the master.

Both confirmed root causes are specific to containers. One root cause is easy to miss. Analysisd sets the size of its thread pools from the CPU count that the pod can see, not from the cgroup CPU quota. On a large node this creates thousands of threads, and those threads starve `wazuh-db`.

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

On the affected worker, `cluster.log` shows two errors for each sync cycle:

```text
ERROR: [Worker worker01] [Agent-info sync] Could not obtain data from wazuh-db: Error 2013 - Error sending HTTP request
ERROR: [Worker worker01] [Agent-info sync] Error synchronizing agent info: Error 2017 - Could not retrieve agents synchronization information from wazuh-db
```

At the same time, cluster transport in the same log stays correct:

```text
INFO: [Worker worker01] [Keep Alive] Successful response from master: keepalive
INFO: [Worker worker01] [Integrity check] Finished in 0.011s. Sync not required.
```

Other signatures occur in the same failure window:

| Where | Signature |
|---|---|
| Worker `ossec.log` | `:router: ERROR: database is locked on endpoint: /v1/agents/sync` |
| Worker `ossec.log` | `wazuh-db: WARNING: After vacuum, the database '0NN' has become just as fragmented or worse` |
| Master `ossec.log` | `wazuh-db: ERROR: Cannot set connection_status for agent <ID>` (repeats every 20 s) |
| Dashboard | `Could not get agents info` / `ERR_BAD_REQUEST - Invalid wazuh-db HTTP request` (HTTP 500) |

The pod stays `Running`. The command `wazuh-control status` reports each daemon as running. Kubernetes therefore finds no problem.

## Step 1: Confirm the fault is agent-info sync, not cluster transport

```bash
kubectl exec -n <namespace> wazuh-manager-master-0 -- /var/ossec/bin/cluster_control -i more
```

The output shows a different condition for each subsystem:

- `Last keep Alive` is recent and `Integrity check` completes. Transport and file sync are correct.
- `Agents-info` shows `Last synchronization: n/a` and `Number of synchronized chunks: 0`. Only the agent-state path is broken.

If keepalive or the integrity check also fail, you have a different problem. Refer to [cluster debugging](./cluster-debugging.md) and to the namespace and DNS section in that guide.

## Step 2: Query the worker wazuh-db HTTP socket

`Agent-info sync` reads the worker-local agent state through an HTTP API on a Unix socket. Query this socket on a failed worker. Then query it on the master to compare the two results.

```bash
kubectl exec -n <namespace> wazuh-manager-worker-0 -- sh -lc \
  'timeout 10 curl --unix-socket /var/ossec/queue/sockets/wdb-http.sock -sv http://localhost/v1/agents/ids'
```

| Node | `GET /v1/agents/ids` | Interpretation |
|---|---|---|
| Correct | `HTTP/1.1 200 OK` with a JSON array of agent IDs | wazuh-db answers normally |
| Failed | `Empty reply from server` (curl exit 52), or no answer before the timeout | The socket accepts and reads the request, then writes no answer |

The socket accepts connections. During the request, `/proc/net/unix` shows an additional connected entry for `wdb-http.sock`. A missing listener is a different failure mode. In this failure mode the socket accepts the request and sends no answer. On the master, `GET /` returns `404`. On the worker the same request does not complete. This shows that the fault applies to all routes, not to one endpoint.

> **Early indicator.** The number of long-lived Unix sockets between `wazuh-analysisd` and `queue/db/wdb` increases before the HTTP path fails. A correct worker stays near 200. A worker that moves toward failure goes above 1000 in about 20 minutes.
>
> ```bash
> kubectl exec -n <namespace> wazuh-manager-worker-0 -- sh -lc \
>   'lsof -p "$(pgrep -x wazuh-analysisd)" -U 2>/dev/null | grep -c "queue/db/wdb"'
> ```

## Step 3: Compare the worker and master agent state

Make sure that the agents are connected and that only the propagation is broken. The manager image has no `sqlite3` command, so use the Python interpreter in the image:

```bash
kubectl exec -n <namespace> <POD> -- /var/ossec/framework/python/bin/python3 -c "
import sqlite3
c = sqlite3.connect('/var/ossec/queue/db/global.db')
for r in c.execute('select id,name,last_keepalive,connection_status,sync_status from agent where id in (20,21,22)'):
    print(r)"
```

The result shows a clear difference between the two nodes. On the worker, the agents are `active`, `last_keepalive` is current, and the sync status is `syncreq_keepalive`. On the master, the same agents are `disconnected`. Their `last_keepalive` value stopped at the moment the sync failed.

The workers also hold the full set of per-agent databases, such as `015.db` and `020.db`. The master holds only `000.db` and `global.db`. This is correct. The workers own the local agent state, and the master depends on the sync to receive it.

## Root cause 1: analysisd thread pools use the node CPU count

Examine this root cause first. The Wazuh logs do not show it.

The `analysisd.*_threads` options have a default value of `0`, which selects automatic sizing. Analysisd then sets each pool size from the CPU set that is visible inside the container. On a large bare-metal node this is the full CPU count of the node, not the cgroup quota of the pod. Use these commands to find the difference:

```bash
kubectl exec -n <namespace> wazuh-manager-worker-0 -- sh -lc '
  echo "nproc:   $(nproc)"
  echo "cpu.max: $(cat /sys/fs/cgroup/cpu.max)"
  echo "threads: $(ps -o nlwp= -p "$(pgrep -x wazuh-analysisd)")"'
```

One worker reported `nproc: 336` with `cpu.max: 800000 100000`. That quota gives 8 cores for each 100 ms period. Analysisd ran about 3,000 threads. The resulting CFS run-queue contention delays the local wazuh-db HTTP request until the request times out. A comparable cluster on a 16-CPU node used the same 8-core quota, ran about 158 threads, and showed no failure.

> **The `nr_throttled` counter does not find this condition.** The failed cluster and the correct cluster both showed `nr_throttled: 0` and `throttled_usec: 0` in `cpu.stat`. The cause is scheduler contention between thousands of runnable threads, not quota throttling. Count the threads. Do not use the throttling counters.

To correct the problem, set each pool explicitly in `/var/ossec/etc/local_internal_options.conf`:

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

Restart the StatefulSet to apply the change. With an 8-vCPU limit, the thread count decreases from about 3,000 to about 50. The wdb HTTP endpoint then answers in less than one millisecond. Before the change, the same request timed out at 5 s.

Select the value from the **cgroup CPU limit**, not from `nproc`. One half of the vCPU limit is a good start. Increase the value only if `events_dropped` occurs. The usual advice keeps thread counts at or below the CPU thread count. Refer to [analysisd tuning](../../troubleshooting/server/analysisd.md#tuning-analysisd-queues-and-threads). Inside a container, the CPU thread count means the cgroup limit. Never keep the value `0` on a large node.

## Root cause 2: storage latency on the wazuh-db paths

`wazuh-db` uses SQLite. Cluster synchronization depends on `wazuh-db`. Latency on the volumes behind `/var/ossec/queue/db` and `/var/ossec/var/db` therefore causes `Agent-info sync` timeouts. Network block storage, such as Ceph RBD, is the usual cause.

| Requirement | Value |
|---|---|
| Write latency | Less than 10 ms p99. Less than 5 ms p99 if you cannot change the storage |
| Sustained IOPS | 1000 or more for each worker node |
| Preferred media | Local NVMe or SSD, or a StorageClass with guaranteed IOPS |

Measure the true performance of the database path with an `fio` test that uses `fdatasync`. This test creates the write pattern of SQLite commits:

```bash
fio --name=wdb --filename=/var/ossec/queue/db/.fio-probe \
    --rw=write --bs=4k --size=64m --ioengine=sync --iodepth=1 --numjobs=1 \
    --fdatasync=1 --time_based --runtime=25 \
    --percentile_list=50:95:99 --group_reporting
rm -f /var/ossec/queue/db/.fio-probe
```

Read the `sync` latency percentiles. One investigated pair of clusters gives a useful scale. The correct cluster measured p50 0.020 ms and p99 0.088 ms. The failed cluster measured p50 1.48 ms, p99 3.79 ms, and a maximum of 52.6 ms. Application-side SQLite commit measurements in the same environment gave p99 values of 18 ms to 19 ms, with occasional values near 300 ms.

If you cannot replace the storage, these options decrease the load. They do not remove the problem:

```ini
wazuh_db.commit_time_min=10
wazuh_db.commit_time_max=50
wazuh_db.open_db_limit=256
wazuh_db.worker_pool_size=4
```

> **Do not stop the analysis at storage latency.** In the investigated case, these options and NVMe-backed storage on both database paths made no difference to the disconnections. The measured latency was real but secondary. The disconnections stopped only after the [analysisd thread-pool change](#root-cause-1-analysisd-thread-pools-use-the-node-cpu-count). Count the threads before you plan a storage migration.

## wazuh-db does not recover after an I/O stall

This behavior is the expected architecture, not a defect. `wazuh-db` runs a worker pool against SQLite in WAL mode. During a severe I/O stall, these threads block in kernel syscalls in an uninterruptible sleep state. This protects data integrity. The process therefore cannot apply its own timeout and restart itself.

The main process stays alive. A liveness probe that examines only the process state finds a correct state. A worker that enters this condition stays in this condition after the initial storage problem ends. To recover, restart `wazuh-db` or restart the pod. Wazuh 5.x keeps the same architectural sensitivity, so an upgrade does not correct a latency-bound environment.

## Health probes for manager pods

Kubernetes cannot detect the stalled socket. A probe is therefore useful, but select a probe with a low cost.

- **Recommended: TCP socket probes.** Use port `55000` (API) or `1515` on the master. Use port `1514` on the workers. These probes start no process and add no socket load.
- **Do not use an exec probe that starts an interpreter.** A `python3` command that opens `/var/ossec/queue/db/wdb` every 30 s adds CPU load and socket churn. This makes the contention worse.
- **To probe wazuh-db directly**, use a native client and a long period. The standard manager image does not contain `socat`, so this probe needs a custom image:

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

## Do not delete the SQLite WAL and SHM files

An `initContainer` that deletes the wazuh-db runtime files before startup looks like a good mitigation:

```yaml
# Do NOT do this
command: ["sh", "-c", "rm -f /var/ossec/queue/db/wdb /var/ossec/queue/db/wdb.lock /var/ossec/queue/db/*.db-wal /var/ossec/queue/db/*.db-shm"]
```

Do not use it. It restores service for a short time and then corrupts data. The `.db-wal` file holds writes that are committed but not checkpointed, such as agent events, FIM data, and syscollector data. The `.db-shm` file coordinates access between processes.

If you delete these files during pending transactions, three results follow:

- The database index becomes permanently corrupt.
- Uncommitted data is lost permanently.
- The same cluster-sync failure returns that the mitigation must correct.

Delete these files only when `wazuh-db` is fully stopped and the operating system released all locks.

## Related

- [Cluster debugging](./cluster-debugging.md) - pod, DNS, namespace, and OOMKilled diagnostics for the same deployment
- [Wazuh on Red Hat OpenShift / OKD](./openshift.md) - SCCs, the s6-overlay UID blocker, and the indexer `vm.max_map_count` init container
- [Persistent storage](./persistent-storage.md) - what a pod restart keeps, and what the image creates again
- [Analysisd, EPS, and dropped events](../../troubleshooting/server/analysisd.md) - queue and thread tuning when throughput, not scheduling, is the constraint
- [Agent disconnections](../../troubleshooting/agents/disconnections.md) - agent-side causes, for an agent that truly sends no data
- [wazuh/wazuh#31841](https://github.com/wazuh/wazuh/issues/31841) - public issue for the same Error 2013, 2017, and 2012 family
