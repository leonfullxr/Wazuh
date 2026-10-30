# Vulnerability record review

This topic covers visible vulnerability inventory records with High or Critical severity. It does not determine whether a particular host is currently affected or whether a vulnerability can be exploited.

The content default filters `vulnerability.severity` to the exact values `High` and `Critical`. A site's configured expectation may change the priority check to another approved value, while the rows remain filtered to High and Critical. The check reports whether that configured expectation matched returned rows. It reads the rolling 24 hours ending at the request time, in UTC, using the vulnerability detection timestamp. This time window selects records by detection time; it does not measure inventory age. Counts are records, not distinct assets, and visibility may be restricted by permissions, retention, indexing delay, or page limits.

A Critical severity record is a review referral under the content default. A site's configured priority expectation may change which severity the priority check reports. A review referral is not a finding of exploitability, exploitation, or current affected state. Checks and sample findings describe returned rows only, and say nothing about records outside the returned page.

The seed has no vulnerability recency check because detections are not a continuous stream, so detection time cannot show whether the inventory or ingestion is current. Inventory scan age is unknown and must be confirmed in the authoritative inventory.

The fixture profile `wazuh-v4-fixture` requires these mappings: `vulnerability.detected_at` as a date; `agent.id` and `vulnerability.id` as keyword identifiers; `vulnerability.severity` as a keyword value; `package.name` and `package.version` as keyword or text values. The profile also projects `agent.name` as a keyword or text value. Missing package versions prevent package-version review. Inventory records may not include the installed state, vendor support status, or a recent inventory timestamp.

Confirm the inventory source, severity mapping, detection-time window, and index permissions. Open the matching records and verify the asset identity, package name, version, and inventory timestamp in the authoritative inventory. Check vendor advisories and the site's supported-version data, then have the asset owner confirm current affected status. Record gaps where the available fields do not answer those questions.

# Runtime KEV context

The server may append deterministic KEV context for each returned CVE. The example pack is synthetic and is not an upstream CISA catalog or a licensing statement. A hit means the CVE is listed in the pinned snapshot; it does not prove host compromise. A miss does not rule out exploitation. The seven-day snapshot age policy can make a result historical or unavailable. Page and initial-answer additions are bounded; if a limit is exceeded, no partial subject annotation is claimed and telemetry rows remain. Current affected state and inventory scan age remain unknown.
