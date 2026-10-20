# Authentication failure review

This topic covers a read-only review of alert records grouped as authentication failures. It does not establish whether an attempt was authorized or whether an account was accessed.

The playbook filters `rule.groups` for the exact value `authentication_failed`. It reads the rolling 24 hours ending at the request time, in UTC. Counts describe matching visible records in that read. Index permissions, retention, indexing delays, and page limits may restrict visibility. A count is a record count, not a count of distinct attempts or sources.

Ten or more matching records in the window is a review referral threshold. It is a reason for an analyst to review the evidence, not an attack verdict. The rule level threshold is 10 or higher. Checks and sample findings describe returned rows only. They do not describe records outside the returned page.

The recency check looks at the newest returned record with a valid timestamp inside the read window and compares its timestamp with the request time. The limit in this seed is a synthetic 3600 seconds; real limits are deployment inputs. Passed means at least one returned record is within that limit. Failed means the newest returned record with a valid timestamp inside the read window is older than the limit. Unknown means the check could not be judged, for example because no rows were returned, the read was unavailable, or no returned timestamp was valid. A denied read is reported as denied. The check says nothing about ingestion health, completeness, or scan age.

The fixture profile `wazuh-v4-fixture` requires these mappings: `@timestamp` as a date; `agent.id` and `rule.id` as keyword identifiers; `rule.level` as an integer; `rule.groups` as a keyword array; and `data.srcip` as an IP address or keyword value. The profile also projects `agent.name` as a keyword or text value. Missing source addresses limit source review; the alert may also lack useful rule detail or consistent timestamps.

Confirm the alert group and mapping with the site administrator. Check the query window, index permissions, retention, and ingestion delay. Open the underlying alert records and compare timestamps, rule details, and source addresses. Check related identity-provider and endpoint records, then ask the system owner whether testing or other approved activity was scheduled. Record uncertainty and keep the conclusion limited to the evidence reviewed.
