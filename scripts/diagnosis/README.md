# Wazuh Diagnosis Script

This script collects diagnostic information from a Wazuh environment and performs upgrade readiness checks. It gathers detailed information from the Wazuh Manager, Indexer and Agent components, and outputs the results into organized directories under `/tmp`.

## Features

- **Comprehensive Diagnostics:**  
  - Retrieves Manager API details (version, configuration, health, logs, hardware, and service status).
  - Collects Indexer API information (cluster health, indices, allocation, settings, nodes stats, and nodes info).
  - Gathers Cluster node details via `cluster_control` and executes per-node API calls for additional status, configuration, and log summary.
  - Retrieves Agent status and additional system files (logs, state files, and groups info).

- **Upgrade Readiness Healthcheck:**  
  - Checks that the Wazuh version is at least 4.5.0.
  - Monitors disk usage on the Wazuh Managers root partition (must be less than 85%).
  - Checks disk usage metrics for all Indexer nodes from the allocation API and flags any nodes with disk usage ≥ 85%.
  - Verifies that Indexer cluster health is green.
  - Confirms that both Manager and Indexer APIs respond with HTTP 200.

## Prerequisites

- **Wazuh Server:** Ensure that Wazuh is installed and running.
- **API Access:** Verify that API credentials (for both Manager and Indexer) are available.
- **Dependencies:**  
  - `curl`
  - `jq` (for JSON processing)
  - `zip` or `tar` (for archiving the report)
  - ANSI-compatible terminal for color output

## Usage

### Default Diagnosis Mode

This mode collects all diagnostic information and generates a detailed ZIP (or TAR.GZ) report in `/tmp`.

```bash
sudo bash diagnosis.sh
```

During execution, the script will prompt for:
- Wazuh API credentials (User, Password, Host, Port)
- Indexer API credentials (User, Password, Host, Port)

The final report is created at:
- `/tmp/wazuh_diagnostic_report.zip` (if zip is available)  
  or  
- `/tmp/wazuh_diagnostic_report.tar.gz` (if zip is not available)

### Healthcheck Mode

This mode performs a focused set of checks to validate if the environment is ready for upgrade. The healthcheck includes:
- Verifying that the Wazuh version is at least 4.5.0.
- Checking that the root disk usage is below 85%.
- Iterating over Indexer nodes to ensure disk usage per node is below 85%.
- Ensuring that the Indexer cluster health is green.
- Confirming that both Manager and Indexer APIs respond with HTTP 200.

Run healthcheck mode with:

```bash
sudo bash diagnosis.sh --healthcheck
```

If any check fails, the script outputs the corresponding issues; otherwise, it confirms that the environment is ready for upgrade.

### Help

Display the usage and option information:

```bash
bash diagnosis.sh --help
```

## Output Structure

The script organizes its output under `/tmp/wazuh_diagnostic_reports` as follows:

- **manager/** – Contains Manager API checks, configuration, health, hardware info, and service status.
- **indexer/** – Contains Indexer API checks and related JSON (including indices, allocation, settings, nodes stats and nodes info).
- **cluster/** – Contains overall cluster health and per-node API calls (for worker nodes).
- **agents/** – Contains agent status information.
- **Base files** – Logs, state files, and groups information are also saved in the base output directory.

After execution, the report is compressed and saved in `/tmp` as either a ZIP or TAR.GZ archive.

