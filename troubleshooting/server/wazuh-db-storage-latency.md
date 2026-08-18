# wazuh-db storage latency

Runbook for a manager whose `wazuh-db` stalls on slow storage. The process stays alive, the daemon reports as running, and cluster synchronization fails without an error that names the disk.

> **Applies to:** Wazuh manager 4.x, on any deployment that holds
> `/var/ossec/queue/db` or `/var/ossec/var/db` on network-backed storage. Common
> examples are Ceph RBD or NFS on Kubernetes, and SAN, NFS, or a general-purpose
> cloud volume on a VM.

## Table of Contents

- [Storage requirements](#storage-requirements)
- [How wazuh-db behaves under I/O stress](#how-wazuh-db-behaves-under-io-stress)
- [Symptoms](#symptoms)
- [Step 1: Detect a stalled worker thread](#step-1-detect-a-stalled-worker-thread)
- [Step 2: Measure the device latency](#step-2-measure-the-device-latency)
- [Step 3: Measure the application-visible commit latency](#step-3-measure-the-application-visible-commit-latency)
- [Tuning wazuh_db is a mitigation, not a fix](#tuning-wazuh_db-is-a-mitigation-not-a-fix)
- [Ceph RBD guidance](#ceph-rbd-guidance)
- [No I/O timeout exists](#no-io-timeout-exists)
- [Related](#related)

## Storage requirements

`wazuh-db` uses SQLite. Agent state, cluster synchronization, FIM data, and syscollector data all pass through it. These are the minimum requirements for the two database paths:

| Requirement | Value |
|---|---|
| Write latency | Less than 10 ms p99 |
| Write latency on network block storage | Less than 5 ms p99 |
| Sustained IOPS | 1000 or more for each worker node |
| Preferred media | Local NVMe or SSD |
| Acceptable cloud media | A volume type with guaranteed IOPS, such as AWS `gp3` or GCP `pd-ssd` |

The paths that must meet these numbers are `/var/ossec/queue/db` and `/var/ossec/var/db`. Network block storage with a latency above 100 ms produces the failure described below on every cycle.

## How wazuh-db behaves under I/O stress

`wazuh-db` runs a worker pool against SQLite in WAL mode. Two properties of that design explain the failure:

- SQLite retries a busy database up to 1000 times on `SQLITE_BUSY`. It does **not** handle I/O errors.
- During an I/O stall the worker threads block inside kernel I/O syscalls. The kernel places them in uninterruptible sleep, which protects data integrity.

The main process stays alive during the stall, so Kubernetes and systemd both see a correct state. No watchdog and no timeout mechanism exists to detect the blocked threads. The process therefore cannot restart itself.

The consequence matters more than the mechanism. The manager does **not** recover after the storage latency ends. To restore service, restart `wazuh-db` or restart the pod or service. This behavior is the expected architecture, not a defect. Feature requests exist for application-level I/O timeouts, worker-thread health monitoring, and an automatic restart after a stall. None of these is available today.

## Symptoms

The failure appears in the cluster and in the API, not in a disk error:

| Where | Signature |
|---|---|
| Worker `cluster.log` | `Error 2013 - Error sending HTTP request` and `Error 2017 - Could not retrieve agents synchronization information from wazuh-db` |
| Worker `ossec.log` | `:router: ERROR: database is locked on endpoint: /v1/agents/sync` |
| Master `ossec.log` | `wazuh-db: ERROR: Cannot set connection_status for agent <ID>` |
| Dashboard | `ERR_BAD_REQUEST - Invalid wazuh-db HTTP request` (HTTP 500) |
| Cluster status | `Agents-info: Last synchronization: n/a` with 0 synchronized chunks |
| Agent state | Agents are `active` in the worker database and `disconnected` in the master database |

## Step 1: Detect a stalled worker thread

A thread in the `D` state is blocked in an uninterruptible kernel I/O wait. This is the most direct evidence that storage, not Wazuh, holds the process:

```bash
ps -eLo pid,stat,comm | grep wazuh-db | grep ' D '
```

Any output means at least one worker thread waits on the disk. Confirm the device side at the same time:

```bash
iostat -x 5 3
```

Read the `await` and `%util` columns for the device behind the two database paths.

## Step 2: Measure the device latency

Measure the write pattern that SQLite commits create. The `--fdatasync=1` option is the important part, because it forces a durable write for each block:

```bash
fio --name=wdb --filename=/var/ossec/queue/db/.fio-probe \
    --rw=write --bs=4k --size=64m --ioengine=sync --iodepth=1 --numjobs=1 \
    --fdatasync=1 --time_based --runtime=25 \
    --percentile_list=50:95:99 --group_reporting
rm -f /var/ossec/queue/db/.fio-probe
```

Read the `sync` latency percentiles and compare them against the [requirements](#storage-requirements).

> The manager container image does not contain `fio`. Run the test from the node
> against the same volume, or attach an ephemeral debug container that has `fio`
> and targets the same mount. Do not add `fio` to a production manager image.

## Step 3: Measure the application-visible commit latency

Where `fio` is not available, an application-side SQLite commit test still shows a trend. Treat the result with care. It measures more than the device:

- The interpreter runtime.
- SQLite processing.
- The filesystem layer.
- The block path to the storage backend.

The result is therefore **application-visible commit latency**, not a device benchmark, and it reads higher than the raw device number. Use it for a before-and-after comparison. Use `fio` for the device itself.

One investigated cluster measured these values across three manager workers after it applied the conservative tuning below:

| Metric | Worker 0 | Worker 1 | Worker 2 |
|---|---|---|---|
| p50 | 5.12 ms | 5.01 ms | 5.09 ms |
| p95 | 10.18 ms | 9.80 ms | 10.58 ms |
| p99 | 18.29 ms | 17.86 ms | 19.21 ms |
| p999 | 57.46 ms | 52.10 ms | 49.56 ms |
| Maximum | 374.77 ms | 290.23 ms | 277.86 ms |
| Commits above 100 ms | 36 | 27 | 30 |

Every percentile improved against the run before the tuning. Every worker still stayed above the 10 ms p99 target. At the same time `events_dropped` was 0 and queue usage was 0.00 on all three workers. Those two values matter. They show that the analysis pipeline was not the constraint, so the remaining latency belongs to the storage path.

## Tuning wazuh_db is a mitigation, not a fix

Four options in `/var/ossec/etc/local_internal_options.conf` change how `wazuh-db` uses the storage:

| Option | Valid range | Effect |
|---|---|---|
| `wazuh_db.commit_time_min` | 1 to 3600 s | Lower bound on transaction commit frequency |
| `wazuh_db.commit_time_max` | 1 to 3600 s | Upper bound on transaction commit frequency |
| `wazuh_db.open_db_limit` | 1 to 4096 | Maximum open database connections |
| `wazuh_db.worker_pool_size` | 1 to 32 | Worker thread pool size |

A conservative starting point:

```ini
wazuh_db.commit_time_min=5
wazuh_db.commit_time_max=10
wazuh_db.open_db_limit=256
wazuh_db.worker_pool_size=4
```

These values reduce write pressure. They do not make slow storage fast, and they do not stop the stall. Measure again after the change and expect an improved profile that still misses the target on storage that cannot meet it.

## Ceph RBD guidance

Ceph RBD is a frequent cause because it is network block storage. If Ceph is mandatory in the environment, the storage team can improve the profile:

- Set `rbd_cache=true` with aggressive write-back.
- Set `rbd_cache_max_dirty` to 64 MB or more.
- Use dedicated SSD-backed OSD pools.
- Guarantee network QoS to the Ceph monitors.
- Target less than 5 ms p99 for the two database paths.

> **The storage team will often report a correct cluster.** A default OpenShift Data
> Foundation class such as `ocs-storagecluster-ceph-rbd` is operator-managed and
> carries no IOPS policy. On SSD-backed ODF, a p50 near 5 ms is normal, and the
> monitoring raises no OSD alert. That report is accurate and it does not clear the
> storage. `wazuh-db` fails on the p99 and on the outliers above 100 ms, not on the
> p50. Ask for the p99 explicitly.

## No I/O timeout exists

`wazuh-db` has no application-level I/O timeout. It uses the SQLite default timeouts only. No configuration option makes the process abandon a blocked write and recover.

An increase of the cluster synchronization timeout was proposed during an escalation on this behavior. The documented `<cluster>` configuration block does not expose such an option, so verify what your version actually accepts before you rely on it. Treat it as unconfirmed.

Two durable options remain:

1. Move `/var/ossec/queue/db` and `/var/ossec/var/db` to storage that meets the [requirements](#storage-requirements).
2. Add a probe that detects the hung instance and restarts it. On Kubernetes, see [health probes for manager pods](../../containerization/kubernetes/agent-info-sync-failures.md#health-probes-for-manager-pods).

## Related

- [Agent-info sync failures](../../containerization/kubernetes/agent-info-sync-failures.md) - the full symptom chain on a clustered manager in Kubernetes, and the analysisd thread-pool cause that this guide does not cover
- [Analysisd, EPS, and dropped events](analysisd.md) - use this guide instead when `events_dropped` is not 0
- [IndexerConnector queue growth](indexer-connector-queue-growth.md) - a different queue that also grows on a saturated manager
- [Kubernetes persistent storage](../../containerization/kubernetes/persistent-storage.md) - StorageClass and volume selection for a containerized manager
