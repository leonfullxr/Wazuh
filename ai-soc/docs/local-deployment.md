# Run AI SOC on your machine

AI SOC polls your Wazuh Indexer with a dedicated read-only account. The local console reads the resulting alert groups, scores, chains, incidents, and analyst work from PostgreSQL. An optional Chat Completions model can assess selected groups in shadow mode.

## Install and configure

Use a Linux machine with Git, GNU Make, Python 3.12.13, uv, Node.js 22.23.3, npm, Docker Engine, and Docker Compose v2. Start a local Docker engine and enter the repository's `ai-soc` directory.

```sh
make local-init
```

Edit `build/local-ai-soc/config.json` for your deployment.

- Set the Indexer URL to its HTTPS address and keep the Indexer certificate's hostname in the URL.
- Set the site ID to a short lowercase identifier, the label to the name you want in the console, and the index pattern to the alerts the deployment may read.
- Set `expected_roles` to the exact role set the dedicated Indexer account receives. Review that it can read every alert in the chosen site and index pattern, then replace the example `full_visibility_attestation` with your review reference.
- Put the trusted Indexer CA PEM in `credentials/indexer-ca.pem` and the account's username and password in `credentials/indexer.json`, under the initialized state directory. Keep the credential and configuration files private to your OS account.

The alert mapping supports Wazuh 4.14.7. Choose a separate `LOCAL_DIR` for an independent database, configuration, and sign-in key.

## Connect a model

Add an `assessment` object inside the site entry in `config.json`. This example points to a local provider that exposes OpenAI-compatible Chat Completions with strict JSON schema output.

```json
"assessment": {
  "enabled": true,
  "base_url": "http://127.0.0.1:11434/v1",
  "model": "your-installed-model",
  "max_calls_per_run": 20,
  "concurrency": 1
}
```

Use the endpoint and model identifier from your provider. For a hosted service, use its HTTPS base URL and add `"credential_file": "/absolute/path/to/provider-key"`. The key file contains only the bearer key and must have mode `0600`. A loopback HTTP model can run without a key. A hosted model receives the bounded evidence included in each submitted assessment.

Leave `assessment` out to run the deterministic workspace alone. The model status in Overview reports attempts, completions, and failures. Assessments on real alerts run in shadow mode. The console reports model activity while the workspace continues to rank alerts and record analyst decisions independently.

## Start and sign in

```sh
make local
```

The launcher builds the console, checks Indexer TLS and the account's roles, prepares the database, then runs the poller and worker. Open the numeric loopback URL it prints in Chromium. On the sign-in screen, choose `runtime/sign-in.key` from the state directory. The launcher creates a fresh key on each start.

Open **Overview** to see the last successful poll. Open **Queue** to inspect ranked groups and their evidence. Use the runtime logs under the state directory to diagnose a source or worker failure.

To use another port or state directory, pass the same values to the relevant commands.

```sh
make local-init LOCAL_DIR=/path/to/private-ai-soc
make local LOCAL_DIR=/path/to/private-ai-soc LOCAL_PORT=8130
```

Stop the foreground process with Ctrl+C or run `make local-down` in a second terminal. Pass the same `LOCAL_DIR` if you selected one. The PostgreSQL volume preserves alerts, scores, incidents, and analysis records between starts. Keep the state directory with its database volume so the stored credentials remain available.

## Deployment boundaries

The local console binds to `127.0.0.1` and is intended for one operator on the machine. The source account uses the Indexer API and has read-only permissions. The hosted AWS deployment has its own identity, model, audit, and infrastructure profile. See [Workspace operations](operations/workspace.md) for database and worker recovery.
