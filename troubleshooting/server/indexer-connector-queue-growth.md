# IndexerConnector Queue Growth: `queue/indexer/` Never Drains

The indexer-connector queue on manager/worker nodes grows without bound (tens of GB per node) and RocksDB SST files accumulate and never purge, even though the indexer cluster is healthy. This guide separates the real drain failures (which need fixing) from growth that is simply the expected steady state for your fleet size.

> Applies to Wazuh 4.8+ (RocksDB-based indexer connector), and to clustered deployments in particular. It assumes the VD internals and the on-disk layout described in [vulnerability-detection.md](vulnerability-detection.md) - read that first if `/var/ossec/queue/` is unfamiliar.
>
> Distilled from two production cases at very different scales: a 5-node cluster (1 master + 4 workers, ~2,000 agents, ~16M vulnerabilities) where `queue/indexer/` reached 274 GB and had a **fixable drain failure**; and a ~70-node, 3-site deployment (~100k agents per cluster) where it reached ~3 TB per node-set and turned out to be **expected by design** - the manager keeps a full RocksDB replica of the vulnerability data, and roaming agents multiply it across nodes. This guide is about telling those two apart.

## Table of Contents

- [Symptoms](#symptoms)
- [First question: is RocksDB actually draining?](#first-question-is-rocksdb-actually-draining)
- [The two stores under `queue/indexer/`](#the-two-stores-under-queueindexer)
- [Root cause 1: indexer credentials missing from the keystore](#root-cause-1-indexer-credentials-missing-from-the-keystore)
- [Root cause 2: unclean shutdown corrupts RocksDB (the cron anti-pattern)](#root-cause-2-unclean-shutdown-corrupts-rocksdb-the-cron-anti-pattern)
- [Root cause 3: "request too large" - `http.max_content_length`](#root-cause-3-request-too-large---httpmax_content_length)
- [Root cause 4: registration flood amplifies disk I/O](#root-cause-4-registration-flood-amplifies-disk-io)
- [High event volume: analysisd dbsync queue](#high-event-volume-analysisd-dbsync-queue)
- [Resetting cleanly on a cluster](#resetting-cleanly-on-a-cluster)
- [Is it even a bug? What growth is expected](#is-it-even-a-bug-what-growth-is-expected)
- [Reclaiming space: compaction and compression](#reclaiming-space-compaction-and-compression)
- [Inventory-packages: partial coverage after a reset](#inventory-packages-partial-coverage-after-a-reset)
- [Appendix: inspecting the RocksDB stores](#appendix-inspecting-the-rocksdb-stores)
- [Related guides](#related-guides)

## Symptoms

- `/var/ossec/queue/indexer/` grows continuously and never shrinks; a partial cleanup frees space that returns within hours or days.
- The growth is concentrated in either `queue/indexer/db/` **or** `queue/indexer/wazuh-states-vulnerabilities-*/` (see [the two stores](#the-two-stores-under-queueindexer)).
- Either recurring connector errors in `ossec.log`, **or no errors at all** while the queue still balloons.
- The indexer (OpenSearch) side is healthy: cluster status green, `0` write thread-pool rejections, `0` pending tasks, disk well under the watermarks. **This rules out the indexer as the bottleneck** - the problem is manager-side.

Typical log signatures on the affected nodes:

```text
indexer-connector: WARNING: The request is too large. Splitting the bulk data.
indexer-connector: ERROR: Failed to parse error body JSON.
indexer-connector: WARNING: Failed to sync agent '<ID>': Failed to get data from the database.
logger-helper: WARNING: Database 'queue/indexer/db/wazuh-states-vulnerabilities-...' was repaired because it was corrupt.
```

## First question: is RocksDB actually draining?

This is the single most useful diagnostic and it decides everything that follows. Data can reach the index (the connector authenticates over mTLS) while RocksDB is completely **inert** - accumulating SST files that it never writes through its own API and therefore never compacts.

Read the RocksDB `LOG` for the vulnerabilities store and look at the cumulative counters:

```bash
find /var/ossec/queue/indexer -name LOG -path '*vulnerabilities*' \
  -exec grep -E "Cumulative (writes|compaction)" {} +
```

Two very different pictures:

| What the LOG shows | Meaning | Action |
|---|---|---|
| `Cumulative writes: 0 writes, 0 keys` and `Cumulative compaction: 0.00 GB write` | RocksDB is **inert** - SST files pile up but nothing is written through RocksDB or compacted. A drain/init failure. | Fix the root cause (usually [the keystore](#root-cause-1-indexer-credentials-missing-from-the-keystore)); cleaning up alone will not help. |
| `Cumulative writes: 36M writes ...` and `Cumulative compaction: 41.31 GB write ...` | RocksDB **is** writing and compacting. Growth may be legitimate. | Check whether the total [plateaus](#is-it-even-a-bug-what-growth-is-expected) or climbs without bound. |

Also confirm the store is not being reopened dirty:

```bash
grep -i "was repaired because it was corrupt" /var/ossec/logs/ossec.log
grep -c "IndexerConnector initialized successfully" /var/ossec/logs/ossec.log
```

A "repaired because corrupt" line at **every** startup, or `0` successful initializations while data still reaches the index, both point to an unclean lifecycle - see root causes 1 and 2.

Quick size breakdown to see where the bytes are and how big the publishing backlog is:

```bash
du -h --max-depth=1 /var/ossec/queue/indexer/ | sort -rh | head
ls -1 /var/ossec/queue/indexer/db/wazuh-states-vulnerabilities-*/*.sst 2>/dev/null | wc -l
```

## The two stores under `queue/indexer/`

For **every** state index there are two RocksDB stores, and they play completely different roles. Knowing which one is large tells you whether you are looking at a backlog or an expected replica.

| Path | Role | Healthy state |
|---|---|---|
| `queue/indexer/db/wazuh-states-vulnerabilities-*` | **Synchronization (replica) DB** - a persistent full copy of every document currently in the `wazuh-states-vulnerabilities` index, so the manager knows what to add/update/delete on the indexer. One key per detected vulnerability. | Large but **bounded** - roughly the size of the index it mirrors, plus RocksDB overhead. Grows with the vulnerability count. |
| `queue/indexer/wazuh-states-vulnerabilities-*` | **Event queue** - documents produced by the scanner that are not yet published to the indexer. Drained continuously. | Near-empty (`Keys in range: 0`) once the indexer is reachable. |

Two things that routinely surprise people:

- **An "empty" event queue can still occupy gigabytes.** Every publish leaves a delete marker (tombstone); until compaction runs, those `.sst` files remain. A queue with `0` live keys holding 1-2 GB of SST files is normal and reclaimable ([manual compaction](#reclaiming-space-compaction-and-compression)).
- **The replica DB is where the bulk lives, and it is *supposed* to.** In the 5-node case the replica was 40 GB of a 41 GB total; the event queue was 114 MB. A large replica is only a problem if it keeps climbing without plateauing, or dwarfs the index it mirrors (see [Is it even a bug?](#is-it-even-a-bug-what-growth-is-expected)).

> **Never `rm` the replica DB on a running system to reclaim space.** The next agent synchronization compares the (now empty) replica against the indexer and **deletes the indexer's documents to match** - wiping real vulnerability data. Reclaim with [compaction](#reclaiming-space-compaction-and-compression) or a [full reset](#resetting-cleanly-on-a-cluster), never a bare delete of `db/`.

## Root cause 1: indexer credentials missing from the keystore

**The primary drain failure.** The connector will happily push documents over mutual TLS with only client certificates configured - which is why the index keeps growing and everything *looks* connected. But the indexer username/password stored in the keystore are used for operations beyond that data path (index/template management and bulk error handling), and without them the connector never completes the initialization lifecycle that triggers SST cleanup and compaction. The store sits inert (see the [`0 writes / 0 compaction`](#first-question-is-rocksdb-actually-draining) signature).

Check whether it is configured on **every** manager/worker node (the store is created under `/var/ossec/queue/keystore/`):

```bash
ls -la /var/ossec/queue/keystore/ 2>/dev/null || echo "keystore not configured"
```

Set it on each node - the command is the source of truth regardless of version-specific paths:

```bash
echo '<INDEXER_USER>'     | /var/ossec/bin/wazuh-keystore -f indexer -k username
echo '<INDEXER_PASSWORD>' | /var/ossec/bin/wazuh-keystore -f indexer -k password
systemctl restart wazuh-manager
```

After configuring it, re-check the RocksDB LOG. In the reference case the counters went from fully inert to `36M writes / 46 GB ingested / 41 GB compacted` - RocksDB became functional immediately. (Compaction only *starts* keeping up; the total may still need a [clean reset](#resetting-cleanly-on-a-cluster) to shed the backlog accumulated while it was inert.)

Reference: [wazuh-keystore tool](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-keystore.html).

## Root cause 2: unclean shutdown corrupts RocksDB (the cron anti-pattern)

A common "mitigation" for this issue is a nightly cron that does `systemctl stop wazuh-manager && rm -rf /var/ossec/queue/indexer/* && systemctl start wazuh-manager`. **Remove it.** It is self-defeating and hides the real problem:

- Stopping the manager mid-sync leaves the RocksDB stores in an **unclean state** - hence the `was repaired because it was corrupt` line at the next startup, which itself blocks proper compaction.
- Wiping the queue while the manager was stopped destroys local delta-tracking state, producing floods of `404 not_found` responses (the manager tries to delete index documents whose local replica no longer exists) and **breaking inventory repopulation for silent agents** (see [inventory-packages coverage](#inventory-packages-partial-coverage-after-a-reset)).

Fix the actual drain (keystore, and the reset below), *then* retire the cron. If you need a safety net while validating, replace it with a disk-usage **alert**, not a destructive restart.

## Root cause 3: "request too large" - `http.max_content_length`

The `WARNING: The request is too large. Splitting the bulk data.` messages mean a connector bulk request exceeded the indexer's `http.max_content_length` (OpenSearch default **100 MB**). The connector splits and retries, but under backpressure new data arrives faster than the split requests drain, so the cycle repeats.

Raise the limit on each **indexer** node in `/etc/wazuh-indexer/opensearch.yml`, then restart the indexers one at a time (wait for `green` between each):

```yaml
http.max_content_length: 250mb
```

> This relieves the symptom, not the cause. Once the connector can actually drain (keystore fixed, clean reset done), the oversized-bulk loop stops on its own. Treat this as a pressure-release valve, not the fix.

## Root cause 4: registration flood amplifies disk I/O

If agents reference agent **groups that do not exist** on the cluster, `wazuh-authd` rejects every enrollment attempt and the agents retry on a loop - thousands of rejected registrations per day, each hammering `global.db`:

```bash
grep "Invalid group" /var/ossec/logs/ossec.log | awk '{print $NF}' | sort | uniq -c | sort -rn
grep -c "Received request for a new agent" /var/ossec/logs/ossec.log
grep -i "After vacuum, the database" /var/ossec/logs/ossec.log   # fragmentation under write pressure
```

Create the missing groups (authd picks up new group directories **without a restart**):

```bash
/var/ossec/bin/agent_groups -a -g <GROUP_NAME> -q
```

This is not the cause of SST accumulation, but it adds continuous I/O pressure that makes every other symptom worse. See also [enrollment key conflicts](../agents/enrollment-key-conflicts.md) for the related `Agent key already in use` warnings.

## High event volume: analysisd dbsync queue

Syscollector deltas feed VD through analysisd's dbsync queue. On busy clusters (and after a reset, when every agent re-pushes a full inventory) that queue can backpressure. Raise it in `/var/ossec/etc/local_internal_options.conf` on each node, then restart:

```ini
analysisd.dbsync_queue_size=65536
```

Confirm you are not silently dropping events either side of this (`events_dropped`, `discarded_count`) - the statistics-file checks in [analysisd.md](analysisd.md#step-1-check-the-statistics-files) apply directly.

## Resetting cleanly on a cluster

Once the keystore is set, do a full VD state reset so RocksDB starts from a clean slate and sheds the backlog. Use the step-by-step procedure in [vulnerability-detection.md -> Full reset of the VD state](vulnerability-detection.md#full-reset-of-the-vd-state).

> **Cluster caveat that catches everyone:** `ossec.conf` is **per-node** - the `<vulnerability-detection>` block does **not** propagate through cluster sync. You must set `<enabled>no</enabled>` on **every** manager and worker individually, not just the master. Disabling it only on the master is a silent no-op on the workers, and the reset appears to "do nothing."

Order of operations for the whole cluster:

1. Stop `wazuh-manager` on **all** nodes.
2. Disable `<vulnerability-detection>` on **each** node's `ossec.conf`.
3. Remove `queue/vd/{inventory,delayed,event}/` and `queue/indexer/` on **all** nodes (`feed/`, `reports/`, `state_track/` are preserved - the CVE feed is ~11 GB and expensive to re-download).
4. Start with VD disabled, delete the `wazuh-states-vulnerabilities-*` index from the indexer, re-enable VD on every node, restart.

The first scan after a reset re-evaluates every agent, so expect elevated CPU/disk while it converges.

## Is it even a bug? What growth is expected

After the drain is genuinely fixed, the queue does **not** shrink to nothing - it plateaus. The local `queue/indexer/db/` replica can be **several times larger than the OpenSearch index it feeds**, and that is normal: VD is a stateful stream of inserts and deletes, and in RocksDB a delete is a **tombstone** (a marker written on top of the data), not an immediate removal. Tombstones and superseded records live until compaction reclaims them, so a high deleted-document ratio in the index (e.g. 3.1M deleted out of 16.9M) is mirrored by a large-but-bounded local store.

So the question is not "is it big?" but "does it **plateau**?":

| RocksDB LOG | Total size trend | Verdict |
|---|---|---|
| `0 writes / 0 compaction` | climbs relentlessly | **Broken** - drain failure. Fix keystore + reset. Do not just clean. |
| writing & compacting | climbs without bound, far past a few x the index | **Escalate** - collect LOGs and open a support case / check the [community issues](#related-guides). |
| writing & compacting | rises then **flattens** and stays flat | **Expected** - size disks for it and (optionally) alert on a ceiling. |

### The definitive test: live data vs. amplification

"Does it plateau?" takes days to observe. RocksDB can answer it directly - compare how much *live* data the store holds against its physical SST footprint, and against the index it mirrors. With a [version-matched `ldb`](#appendix-inspecting-the-rocksdb-stores):

```bash
DB=/var/ossec/queue/indexer/db/wazuh-states-vulnerabilities-<cluster>
ldb --db=$DB get_property rocksdb.estimate-live-data-size   # real data held
ldb --db=$DB get_property rocksdb.total-sst-files-size      # physical footprint
ldb --db=$DB get_property rocksdb.levelstats                # files/size per level
```

- **`total-sst-files-size` ~ 1.1-1.15 x `estimate-live-data-size`** -> normal. Leveled compaction targets ~10-15% space amplification; healthy, nothing to fix.
- **`estimate-live-data-size` ~ the `wazuh-states-vulnerabilities` index size** (`_cat/indices`) -> the replica is a faithful copy. The bytes are legitimate.
- **`total-sst-files-size` >> live data (2x+)** -> tombstone/SST bloat compaction has not reclaimed yet -> run [manual compaction](#reclaiming-space-compaction-and-compression).

If the *live data itself* is enormous, the store is honestly holding that many vulnerabilities - the next part explains why, and it is not a leak.

### Why it is so large at scale

Two design facts, confirmed by the development team, make the replica legitimately huge on large fleets:

- **Size tracks vulnerabilities, not agents.** Every (agent, package, CVE) match is one ~1-2 KB document in the replica. As a rough field/lab guide, budget on the order of **~1.5 GB per 100 agents' worth of vulnerabilities** - so ~100k agents approaches ~1 TB *per node* before duplication. Dense, EOL, or long-support-tail OSes push it higher.
- **Roaming agents multiply it across nodes.** Each manager keeps a replica for the agents it has seen. When a load balancer moves agents between managers, the same vulnerability documents come to rest on **every** node the agent touched. Across a large cluster this is the dominant multiplier - it is how a ~1 TB/node replica becomes ~3 TB spread over a 3-site, ~70-node deployment.

> **This is inherent to the 4.x architecture, not a per-site misconfiguration.** The manager-side replica exists so each node can reconcile its slice of the index. The development team's position is that it is resolved structurally in **Wazuh 5.0**, whose new VD design stores vulnerabilities only in the indexer and drops the per-node replica. On 4.x you *manage* the footprint (compaction, compression, disk sizing); you do not eliminate it.

Reference case, condensed timeline - the evidence that separated "bug" from "expected":

| Stage | `queue/indexer/` growth | RocksDB state |
|---|---|---|
| Broken (no keystore, nightly cron wiping) | ~19 GB/h across cluster (~46 GB/24h on the worst node) | inert - SST accumulate |
| Keystore set + full VD reset on all nodes | drops sharply | writing & compacting |
| Registration flood fixed | ~0.5 GB/h and falling | I/O pressure relieved |
| **Steady state** | **~40-48 GB/node, +3 GB / 48h** | **plateau = expected for the scale** |

For ~1,920 agents with ~16M vulnerabilities, ~40-48 GB/node was the legitimate steady state; a good alert threshold for that fleet was ~55-60 GB/node. Your numbers scale with agent count, CVE density, and inventory churn - measure your own plateau rather than copying these.

Notes:

- **Reclaim before concluding it is too big.** Much of a startling `du` figure can be uncompacted tombstones. Run [manual compaction](#reclaiming-space-compaction-and-compression) first, then measure the plateau.
- **High-churn agents inflate the *other* state indices.** Agents with heavy ephemeral-port turnover - Docker Swarm nodes are the classic example - generate constant create+delete cycles in `wazuh-states-inventory-ports`, which is pure SST churn. Reduce syscollector frequency or scope for those groups, or filter at the source ([flooding.md](../agents/flooding.md#step-2-reduce-noise-at-the-source), [docker/swarm.md](../../containerization/docker/swarm.md)).

## Reclaiming space: compaction and compression

When the [live-data test](#the-definitive-test-live-data-vs-amplification) shows the physical footprint sitting well above the live data, the excess is recoverable tombstones. Two levers, in order of preference.

### Manual compaction (reclaim now)

RocksDB compacts on its own schedule, but you can force it - the fastest way to reclaim tombstone space from both the event queue and the replica DB. It needs exclusive access, so **stop the manager first** (a running manager holds the DB lock and `ldb` cannot open it), using a [version-matched `ldb`](#appendix-inspecting-the-rocksdb-stores):

```bash
systemctl stop wazuh-manager
for DB in /var/ossec/queue/indexer/wazuh-states-vulnerabilities-* \
          /var/ossec/queue/indexer/db/wazuh-states-vulnerabilities-*; do
  ldb --db="$DB" compact
done
systemctl start wazuh-manager
```

In lab tests an empty-but-bloated event queue dropped from 1.5 GB to under 1 MB this way. Compaction is CPU- and IO-heavy and can run for a long time on a multi-hundred-GB replica - schedule it, and treat it as a periodic chore rather than a permanent fix (tombstones re-accumulate as vulnerabilities are resolved and agents are removed).

> This is the supported, durable version of the destructive nightly cron in [root cause 2](#root-cause-2-unclean-shutdown-corrupts-rocksdb-the-cron-anti-pattern): same goal (reclaim space), but it compacts in place instead of wiping delta state, so it does not cause 404 data loss. Still, prefer letting RocksDB self-compact and only reach for this under real disk pressure.

### Compression (shrink the footprint)

Stock 4.14.x builds have historically shipped RocksDB with **no effective compression** for these stores - verify on your build:

```bash
grep -A10 "Compression algorithms supported" \
  /var/ossec/queue/indexer/db/wazuh-states-vulnerabilities-*/LOG | grep -i "zstd\|bzip2"
# stock builds have shown "kZSTD supported: 0"
```

The development team's testing found **ZSTD** the clear winner - roughly **halving** the replica (e.g. 5.1 GB -> 2.1 GB, ~60%) at negligible CPU, where BZip2 shrank it similarly but at far higher CPU. On builds that expose it, compression and compaction parallelism are tunable via `local_internal_options.conf`:

| Option | Default | Range | Effect |
|---|---|---|---|
| `indexer.rocksdb_background_jobs` | 2 | 2-16 | Compaction/flush threads. The default of 2 is low for large fleets; raising it (e.g. 8) helps compaction keep pace with thousands of agents. |
| `indexer.rocksdb_compression_level` | 3 | 3-22 | ZSTD level. Higher = smaller but more CPU; gains above the default are marginal in practice. |
| `indexer.rocksdb_compression_parallel_threads` | 1 | 1-12 | Parallelism for compression. |
| `indexer.rocksdb_max_sub_compactions` | 1 | 1-12 | Parallelism within a compaction. Note that `background_jobs x max_sub_compactions` bounds total threads. |

> **Availability is version-dependent.** ZSTD support and these options arrived through development builds during this investigation. On a stock install, confirm ZSTD shows `supported: 1` in the LOG and that the option is honoured before relying on either. Changing compression only affects data written afterwards, so it takes a store rebuild (a [reset](#resetting-cleanly-on-a-cluster), or removal + rebuild) to apply to existing data. Do **not** hand-swap `/var/ossec/lib` RocksDB libraries from another host - mismatched `glibc`/`libstdc++` breaks the manager (see the [appendix](#appendix-inspecting-the-rocksdb-stores)). If you need this on 4.x, raise it with Wazuh support rather than patching binaries yourself.

`TTL`/periodic compaction (RocksDB default 30 days) does **not** take effect under the leveled compaction these stores use - do not rely on it to cap growth.

## Inventory-packages: partial coverage after a reset

A frequent aftermath of the destructive-cron workaround: after everything stabilizes, `wazuh-states-inventory-packages` shows **low coverage** - only a fraction of active agents appear, and even the agents that do appear carry a **subset** of their packages (e.g. the manager's SQLite has 770 packages for an agent but only ~179 reached the index). The missing set is not random - it includes exactly the packages an analyst cares about for CVE matching (`bash`, `apt`, `dpkg`, `openssl`, `lib*`, ...).

Why it happens:

- **Packages lag processes/ports.** All three inventories fire from the same syscollector cycle, but packages consistently complete later (tens of seconds to minutes), so a snapshot taken too soon looks empty.
- **Silent agents don't repopulate.** Agents that only send `dbsync` deltas (rather than a full Rsync) never re-push their full inventory after the local delta state was wiped by the cron - so the index keeps whatever partial state it had.

Fix - clean the packages state with the managers **stopped**, then force a full resync:

```bash
systemctl stop wazuh-manager    # on all nodes
rm -rf /var/ossec/queue/indexer/wazuh-states-inventory-packages-*
rm -rf /var/ossec/queue/indexer/db/wazuh-states-inventory-packages-*
rm -rf /var/ossec/queue/harvester/system_event/     # delta-tracking state
systemctl start wazuh-manager
# then delete the index so it rebuilds from scratch:
curl -X DELETE "https://<INDEXER_IP>:9200/wazuh-states-inventory-packages-*/" \
  -u <INDEXER_USER>:<INDEXER_PASSWORD> -k
```

Force a full inventory resync **without restarting every agent** (impractical at scale) - pick one:

- Restart the manager's VD module, **or**
- Append a timestamped comment to a shared group's `agent.conf`; the cluster regenerates `merged.mg`, agents reload on the checksum change (`SIGHUP`), and syscollector `scan_on_start` re-pushes the full inventory:

  ```bash
  printf '<!-- force resync %s -->\n' "$(date +%Y%m%d_%H%M%S)" \
    >> /var/ossec/etc/shared/default/agent.conf
  ```

- Rebalance agents across workers if the reset left them lopsided: `PUT /agents/reconnect?agents_list=<IDS>`.

Coverage climbs over the following hours (in the reference case, from ~26% to ~84% of active agents). Verify the count is rising rather than frozen; a flat count after several hours means the resync did not reach the silent agents and the cleanup above should be repeated.

## Appendix: inspecting the RocksDB stores

**Match the `ldb` version to Wazuh's embedded RocksDB.** Wazuh 4.14.x embeds RocksDB 8.x (8.3.2 in the observed case). Distro packages are older - Ubuntu 22.04's `rocksdb-tools` ships `ldb` 6.11.4, which fails on the newer format with `Corruption: unknown checksum type 4` or an assertion. Wazuh ships `librocksdb.so.8` but no standalone `ldb`/`sst_dump`, so to dump a store you must build `ldb` from RocksDB 8.3.2 source. For most triage the LOG counters and `du` are enough and avoid this entirely:

```bash
# Which version Wazuh is using
grep -i "RocksDB version" /var/ossec/queue/indexer/db/wazuh-states-vulnerabilities-*/LOG | head -1

# Largest SST files in the vulnerabilities store
du -aSh /var/ossec/queue/indexer/db/wazuh-states-vulnerabilities-*/ | sort -rh | head

# If you built a matching ldb, count keys per agent (spot duplicate/orphan churn)
ldb --db=/var/ossec/queue/indexer/db/wazuh-states-vulnerabilities-wazuh_cluster dump \
  | grep -o '"id":"[0-9]*"' | sort | uniq -c | sort -rn | head
```

Cheap sizing properties (no full dump required):

```bash
DB=/var/ossec/queue/indexer/db/wazuh-states-vulnerabilities-<cluster>
ldb --db=$DB get_property rocksdb.estimate-live-data-size   # real data held
ldb --db=$DB get_property rocksdb.total-sst-files-size      # physical SST footprint
ldb --db=$DB get_property rocksdb.levelstats                # files + MB per level (~10x each step)
ldb --db=$DB dump --count_only                              # key count + value-size distribution
```

> **Do not build or copy `ldb` (or the manager's RocksDB libraries) from a mismatched base OS.** Wazuh's binaries are built for broad backward compatibility (a CentOS 7-era `glibc`/`libstdc++`). Libraries compiled on a newer host fail at load with errors like `GLIBC_2.38 not found`, `GLIBCXX_3.4.29 not found`, or `CXXABI_1.3.13 not found`, and can leave `wazuh-modulesd` unable to start. Build `ldb` to match RocksDB 8.x on a compatible base and use it read-only against a **stopped** manager's stores.

**Packages silently skipped in CVE matching.** Non-standard version strings break the version comparator and drop those packages from scanning - worth a grep, because the affected packages get *no* vulnerability evaluation:

```bash
grep -iE "Error creating VersionObject|Unable to compare versions" /var/ossec/logs/ossec.log \
  | sort | uniq -c | sort -rn
# e.g. "6.7.8 (32670)" (parentheses) or "0.9_rc" (rc suffix)
```

## Related guides

- [vulnerability-detection.md](vulnerability-detection.md) - VD on-disk layout, diagnostics, and the full reset procedure linked above
- [analysisd.md](analysisd.md) - dropped-event statistics and queue tuning (`dbsync_queue_size` lives in the same file)
- [../agents/enrollment-key-conflicts.md](../agents/enrollment-key-conflicts.md) - `Agent key already in use`, duplicate IDs, force re-enrollment
- [../agents/flooding.md](../agents/flooding.md) - reducing event/inventory volume at the source
- [../../indexer/disk-management.md](../../indexer/disk-management.md) - indexer-side disk watermarks (rule these out first: this issue is manager-side)
- [../../scripts/diagnosis/](../../scripts/diagnosis/) - one-command environment snapshot (manager, indexer, cluster, agents)
- **Related but distinct:** on multi-site deployments that reuse agent IDs across clusters, the vulnerability dashboard can show one agent's CVEs under a *different* agent from another cluster - an ID collision in the shared `wazuh-states-vulnerabilities` index, not a queue-growth problem. Give each cluster a distinct agent-ID space / cluster name rather than chasing it here.
- Community reports of the same symptom: wazuh/wazuh issues [#24243](https://github.com/wazuh/wazuh/issues/24243), [#30476](https://github.com/wazuh/wazuh/issues/30476), [#31848](https://github.com/wazuh/wazuh/issues/31848), [#34551](https://github.com/wazuh/wazuh/issues/34551)
