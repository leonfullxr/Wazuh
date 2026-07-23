# Analysisd, EPS, and Dropped Events

Guide for a Wazuh manager that is dropping events: reading the statistics files, measuring events per second (EPS), tuning analysisd queues and threads, and deciding when tuning stops and scaling starts.

This guide also covers general manager resource monitoring - the statistics files below are the single most useful signal for "does my server need more resources?".

## Table of Contents

- [Step 1: Check the statistics files](#step-1-check-the-statistics-files)
- [Step 2: Rule out the basics](#step-2-rule-out-the-basics)
- [Measuring EPS](#measuring-eps)
- [The EPS limit (`<limits><eps>`) throttles bursts](#the-eps-limit-limitseps-throttles-bursts)
- [Event size limit (`Message too long`)](#event-size-limit-message-too-long)
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

Both counters at zero means the manager is keeping up - look at the agent side instead ([../agents/flooding.md](../agents/flooding.md)). Non-zero and growing means the manager is the bottleneck: continue below.

You can also query queue usage, processed counts, and discards per daemon live through the API: `GET /manager/daemons/stats` ([queuing mechanisms reference](https://documentation.wazuh.com/current/user-manual/manager/wazuh-server-queue.html)).

Reference: [Statistics files](https://documentation.wazuh.com/current/user-manual/reference/statistics-files/index.html)

## Step 2: Rule out the basics

Before tuning queues, discard the cheap explanations:

```bash
# Disk space - a full /var stalls everything
df -h

# Errors and warnings in the manager log
grep -iE 'err|warn' /var/ossec/logs/ossec.log

# Cluster integrity (on clustered deployments)
/var/ossec/bin/cluster_control -i
```

For a full snapshot (manager, indexer, cluster, agents) in one command, run the [diagnosis script](../../scripts/diagnosis/).

## Measuring EPS

To quantify the load, measure real EPS at the manager. The procedure (temporarily enable `<logall>`, run a counting script against `archives.log`, disable `<logall>` again) is packaged in [`../../scripts/EPS/`](../../scripts/EPS/) - use that rather than re-implementing it.

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

> Remember to set `<logall>` back to `no` and restart the manager when done - archives will otherwise fill the disk.

By default Wazuh does not cap EPS - sustainable EPS is a function of your hardware. Compare the measured EPS against the [architecture sizing recommendations](https://documentation.wazuh.com/current/quickstart.html#requirements) to know whether you are simply over capacity. Note the optional `<limits><eps>` ceiling below, which *deliberately* drops events above a configured rate.

## The EPS limit (`<limits><eps>`) throttles bursts

Dropped events are not always queue saturation. Wazuh can enforce a **deliberate** events-per-second ceiling per node via `<global><limits><eps>`. It is optional and often unset on a self-hosted install, but is set to the sized capacity on managed or capacity-planned deployments:

```xml
<limits>
  <eps>
    <maximum>5000</maximum>
    <timeframe>1</timeframe>
  </eps>
</limits>
```

Events arriving above `maximum` (averaged over `timeframe` seconds, via a credit bucket) are throttled - held back, and dropped if the burst is sustained. Two consequences catch people out:

- **The limit is per node.** In a cluster the effective ceiling is `maximum x number of nodes` *only if traffic is spread evenly*. If syslog or agents pin to one node (see [load balancing syslog](../../integrations/syslog/README.md#load-balancing-syslog-across-cluster-workers)), that node hits its own limit and drops while the others sit idle - the drops look like a capacity problem when the real issue is distribution.
- **Bursts matter more than the average.** A source comfortably under its average EPS across a day can still blow past `maximum` for a few minutes - scheduled batch forwarding, a login storm, a rebooted device flushing its backlog. Those short spikes throttle even though the 24-hour average looks fine. Size for the **peak burst**, not the mean.

Check the configured limit and whether events are being dropped:

```bash
grep -A4 "<limits>" /var/ossec/etc/ossec.conf
cat /var/ossec/var/run/wazuh-analysisd.state | grep -Ei "events_dropped|events_received"
```

If real peaks legitimately exceed the ceiling and you cannot reduce the source at collection time, raise `maximum` (only if the hardware can sustain it) and add worker nodes - but extra nodes help only once traffic actually distributes across them.

## Event size limit (`Message too long`)

Individual events (not just the queue) have a hard size cap: a single event over 65535 bytes (64 KiB, minus ~256 bytes reserved for headers) is skipped, not truncated. The signatures:

```text
DEBUG: Event size exceeds the maximum allowed limit of 65535 bytes.
ERROR: Message too long to send to Wazuh.  Skipping message...
DEBUG: +++ ERROR: Message longer than buffer socket for Wazuh. Consider increasing rmem_max. Skipping message...
```

This is a per-record problem, not a volume problem: one log line is enormous, almost always because an entire file was shipped as a single event instead of one event per line. Common causes and fixes:

- **A whole log file sent as one line.** An S3 object, a multi-line stack trace, or a batch export collapsed into one record. Fix at the source: emit one log per line; for CSV, include a header row so each row is decoded separately. This is a frequent [AWS custom-bucket](../../cloud/aws-sqs-troubleshooting.md#event-too-large---message-too-long) failure (a multi-MB text file shipped whole).
- **A genuinely large but valid record.** The `Consider increasing rmem_max` hint refers to the OS UDP receive-buffer for the analysisd socket (`sysctl net.core.rmem_max`); raising it can help a borderline case, but it does not lift the 64 KiB per-event ceiling. Splitting the record at the source is the real fix.

The event is dropped before decoding, so it never reaches a rule: it will not appear in `alerts.json` or `archives.json`. If entire sources go missing, grep the manager log for `Message too long` before suspecting decoders or rules.

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
- Queue sizes are counted in **events, not bytes** - default 16,384, maximum 2,000,000.
- Full limits and defaults: [internal configuration reference](https://documentation.wazuh.com/current/user-manual/reference/internal-options.html) and [queuing mechanisms](https://documentation.wazuh.com/current/user-manual/manager/wazuh-server-queue.html#wazuh-analysis-engine-queue-queue-and).

### How much RAM does a bigger queue cost?

Rule of thumb: `RAM ~ queue_size x average event size`, consumed only while the queue is occupied; larger queues do not pre-reserve memory. For a 65,536-event queue:

| Average event size | Approx. RAM when full |
|---|---|
| 1 KB | ~64 MB |
| 2 KB | ~128 MB |
| 5 KB | ~320 MB |
| 10 KB | ~640 MB |

Real usage runs somewhat higher than the raw log size because the manager builds temporary JSON structures while decoding (plus a fixed ~0.5 MB of pointer overhead per 65k-entry queue). To estimate for your environment: measure the average size of your dominant event source (Windows event channel events are typically several KB; syscollector events can be larger), multiply by the queue size, and count only the queues that actually fill under load.

## When tuning is not enough: reduce or scale

If events are still dropped after queue tuning:

1. **Reduce the input.** Review the top-alerting rules and filter noise **at the agent side** - excluding events at collection saves agent CPU, bandwidth, and manager throughput simultaneously. Silencing rules on the manager still pays the full ingestion cost. Techniques (event channel `<query>`, `localfile` `<exclude>`, rule overwrites) are in [../agents/flooding.md](../agents/flooding.md#step-2-reduce-noise-at-the-source).
2. **Distribute the workload.** A single manager is a natural bottleneck; deploy a [Wazuh server cluster](https://documentation.wazuh.com/current/user-manual/wazuh-server-cluster/index.html) with two or more nodes (separate VMs) and split the agent load - typically behind a TCP load balancer on ports 1514/1515.
3. **Scale the indexer tier** if the bottleneck is downstream - see [adding indexer nodes](https://documentation.wazuh.com/current/user-manual/wazuh-indexer-cluster/add-wazuh-indexer-nodes.html) and the guides in [`../../indexer/`](../../indexer/).

When investigating further, capture the full `wazuh-analysisd.state`, `wazuh-remoted.state`, and `/var/ossec/logs/ossec.log` files together - the ratios between `received`, `processed`, and `dropped` identify the saturated stage.

## Related guides

- [../agents/flooding.md](../agents/flooding.md) - the agent-side half of the same problem, plus noise-reduction techniques
- [../../scripts/EPS/](../../scripts/EPS/) - packaged EPS measurement script
- [../../scripts/diagnosis/](../../scripts/diagnosis/) - full environment diagnostic collection
