# Analysisd, EPS, and Dropped Events

Guide for a Wazuh manager that is dropping events: reading the statistics files, measuring events per second (EPS), tuning analysisd queues and threads, and deciding when tuning stops and scaling starts.

This guide also covers general manager resource monitoring — the statistics files below are the single most useful signal for "does my server need more resources?".

## Table of Contents

- [Step 1: Check the statistics files](#step-1-check-the-statistics-files)
- [Step 2: Rule out the basics](#step-2-rule-out-the-basics)
- [Measuring EPS](#measuring-eps)
- [Tuning analysisd queues and threads](#tuning-analysisd-queues-and-threads)
  - [How much RAM does a bigger queue cost?](#how-much-ram-does-a-bigger-queue-cost)
- [When tuning is not enough: reduce or scale](#when-tuning-is-not-enough-reduce-or-scale)
- [Related guides](#related-guides)

## Step 1: Check the statistics files

Two state files on the manager tell you immediately whether events are being lost:

| File | Key variable | Meaning |
|---|---|---|
| `/var/ossec/var/run/wazuh-analysisd.state` | `events_dropped` | Events discarded by the analysis engine (queues full / lack of resources) |
| `/var/ossec/var/run/wazuh-remoted.state` | `discarded_count` | Messages from agents discarded by the reception daemon |

```bash
cat /var/ossec/var/run/wazuh-analysisd.state | grep -Ei "processed|dropped|decoded|received|decode|winevt"
cat /var/ossec/var/run/wazuh-remoted.state | egrep 'discarded|queue_size|evt_count'
```

Both counters at zero means the manager is keeping up — look at the agent side instead ([../agents/flooding.md](../agents/flooding.md)). Non-zero and growing means the manager is the bottleneck: continue below.

You can also query queue usage, processed counts, and discards per daemon live through the API: `GET /manager/daemons/stats` ([queuing mechanisms reference](https://documentation.wazuh.com/current/user-manual/manager/wazuh-server-queue.html)).

Reference: [Statistics files](https://documentation.wazuh.com/current/user-manual/reference/statistics-files/index.html)

## Step 2: Rule out the basics

Before tuning queues, discard the cheap explanations:

```bash
# Disk space — a full /var stalls everything
df -h

# Errors and warnings in the manager log
grep -iE 'err|warn' /var/ossec/logs/ossec.log

# Cluster integrity (on clustered deployments)
/var/ossec/bin/cluster_control -i
```

For a full snapshot (manager, indexer, cluster, agents) in one command, run the [diagnosis script](../../scripts/diagnosis/).

## Measuring EPS

To quantify the load, measure real EPS at the manager. The procedure (temporarily enable `<logall>`, run a counting script against `archives.log`, disable `<logall>` again) is packaged in [`../../scripts/EPS/`](../../scripts/EPS/) — use that rather than re-implementing it.

The core of it, for reference:

```bash
#!/bin/bash
logfile="archives.log"
interval=1  # seconds

prev_entries=$(grep -E "^[0-9]{4} [A-Za-z]{3} [0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}" "$logfile" | wc -l)
while true; do
  sleep "$interval"
  current_entries=$(grep -E "^[0-9]{4} [A-Za-z]{3} [0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}" "$logfile" | wc -l)
  new_events=$((current_entries - prev_entries))
  EPS=$(bc -l <<< "scale=2; $new_events / $interval")
  echo "[INFO] - $(date '+%Y-%m-%dT%H:%M:%S') - Events: $new_events | EPS: $EPS"
  prev_entries=$current_entries
done
```

> Remember to set `<logall>` back to `no` and restart the manager when done — archives will otherwise fill the disk.

Wazuh does not impose a per-node EPS limit; sustainable EPS is a function of your hardware. Compare the measured EPS against the [architecture sizing recommendations](https://documentation.wazuh.com/current/quickstart.html#requirements) to know whether you are simply over capacity.

## Tuning analysisd queues and threads

If `events_dropped` grows under burst load but average EPS is within capacity, enlarging analysisd's internal queues and thread pools usually absorbs the spikes. Add to `/var/ossec/etc/local_internal_options.conf`:

```ini
analysisd.event_threads=8
analysisd.rule_matching_threads=8
analysisd.decode_event_queue_size=100000
analysisd.decode_output_queue_size=100000
analysisd.decode_syscollector_queue_size=100000
```

Then restart the manager and watch `wazuh-analysisd.state` again.

Notes:

- Thread options (`analysisd.event_threads`, `analysisd.rule_matching_threads`, `analysisd.winevt_threads`) max out at **32**. Keep them at or below your CPU thread count.
- Queue sizes are counted in **events, not bytes** — default 16,384, maximum 2,000,000.
- Full limits and defaults: [internal configuration reference](https://documentation.wazuh.com/current/user-manual/reference/internal-options.html) and [queuing mechanisms](https://documentation.wazuh.com/current/user-manual/manager/wazuh-server-queue.html#wazuh-analysis-engine-queue-queue-and).

### How much RAM does a bigger queue cost?

Rule of thumb: `RAM ≈ queue_size × average event size`, consumed **only while the queue is occupied** — larger queues do not pre-reserve memory. For a 65,536-event queue:

| Average event size | Approx. RAM when full |
|---|---|
| 1 KB | ~64 MB |
| 2 KB | ~128 MB |
| 5 KB | ~320 MB |
| 10 KB | ~640 MB |

Real usage runs somewhat higher than the raw log size because the manager builds temporary JSON structures while decoding (plus a fixed ~0.5 MB of pointer overhead per 65k-entry queue). To estimate for your environment: measure the average size of your dominant event source (Windows event channel events are typically several KB; syscollector events can be larger), multiply by the queue size, and count only the queues that actually fill under load.

## When tuning is not enough: reduce or scale

If events are still dropped after queue tuning:

1. **Reduce the input.** Review the top-alerting rules and filter noise **at the agent side** — excluding events at collection saves agent CPU, bandwidth, and manager throughput simultaneously. Silencing rules on the manager still pays the full ingestion cost. Techniques (event channel `<query>`, `localfile` `<exclude>`, rule overwrites) are in [../agents/flooding.md](../agents/flooding.md#step-2-reduce-noise-at-the-source).
2. **Distribute the workload.** A single manager is a natural bottleneck; deploy a [Wazuh server cluster](https://documentation.wazuh.com/current/user-manual/wazuh-server-cluster/index.html) with two or more nodes (separate VMs) and split the agent load — typically behind a TCP load balancer on ports 1514/1515.
3. **Scale the indexer tier** if the bottleneck is downstream — see [adding indexer nodes](https://documentation.wazuh.com/current/user-manual/wazuh-indexer-cluster/add-wazuh-indexer-nodes.html) and the guides in [`../../indexer/`](../../indexer/).

When investigating further, capture the full `wazuh-analysisd.state`, `wazuh-remoted.state`, and `/var/ossec/logs/ossec.log` files together — the ratios between `received`, `processed`, and `dropped` identify the saturated stage.

## Related guides

- [../agents/flooding.md](../agents/flooding.md) — the agent-side half of the same problem, plus noise-reduction techniques
- [../../scripts/EPS/](../../scripts/EPS/) — packaged EPS measurement script
- [../../scripts/diagnosis/](../../scripts/diagnosis/) — full environment diagnostic collection
