# Wazuh AI SOC

AI SOC is a read-only Wazuh SOC assistant. It plans an analyst's question by topic, gathers bounded evidence for each topic, and returns a separate judgment for each one. It does not change Wazuh configuration or perform active response.

## Fresh clone setup

On Linux x86_64, install Git, GNU Make, CPython 3.12.13, [uv 0.11.28](https://docs.astral.sh/uv/), Docker Engine with its daemon available, and bubblewrap at `/usr/bin/bwrap` with working user and network namespaces. Install `/usr/bin/gcc` with version output exactly `gcc (Debian 12.2.0-14+deb12u1) 12.2.0`, with `cc` available and the static C runtime installed. Also install `curl`, `unzip`, `tar`, `xz`, and `sha256sum`. The `make ci-check` image reproducibility step needs at least 2 GiB free on `/dev/shm`. Then run these commands from the repository root, in order:

```sh
make bootstrap
make ci-check
```

`make bootstrap` installs the locked Python, UI, and contract TypeScript dependencies, then fetches and verifies the pinned platform tools, browser, provider, and scanner inputs. The checks run offline after setup. The tests use synthetic fixtures and do not validate a live Wazuh site or cloud deployment.

### Local development

Run `make fixture` to build `build/dev-fixture/build-a` from the synthetic content seed. The source is committed in a disposable Git repository and its approval is ephemeral and fixture-only.

Run `make dev` (or `make dev PORT=8010`) to start the composed REST and MCP applications on loopback. It uses synthetic identities, in-memory non-durable state and audit, and a deterministic synthetic model that is not a quality signal. The server refuses live or cloud environment variables.

Use the values in `build/dev-fixture/credentials.json` for authenticated requests. The bootstrap response sets a `__Host-soc-csrf` cookie and returns a `csrf_token`; copy both into the later requests:

```sh
credentials=build/dev-fixture/credentials.json
base_url=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["base_url"])' "$credentials")
header=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["alb_header_name"] + ": " + d["alb_assertion"])' "$credentials")
origin=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["browser_origin"])' "$credentials")
curl -si -H "$header" "$base_url/v1/bootstrap"
# Set cookie="__Host-soc-csrf=<value>" and csrf="<csrf_token>" from the output above.
curl -s -H "$header" -H "Origin: $origin" -H "Cookie: $cookie" -H "X-SOC-CSRF: $csrf" \
  -H 'Content-Type: application/json' \
  -d '{"question":"LDAP is not working. Recommend what to check next.","environment_id":"synthetic","timezone":"UTC","model_id":"synthetic-model"}' \
  "$base_url/v1/questions"
curl -s -o /dev/null -w '%{http_code}\n' -H "$header" -H "Origin: $origin" -H "Cookie: $cookie" \
  -H "X-SOC-CSRF: $csrf" -H 'Content-Type: application/json' \
  -d '{"question_id":"<question_id>","environment_id":"synthetic","feedback_receipt":"<feedback_receipt>","kind":"wrong"}' \
  "$base_url/v1/feedback"
```

The answer's `question_id` and `feedback_receipt` fill the feedback request, which returns 202. The fixture answers LDAP questions from its configured playbook when the question says the service is "not working" and asks for a recommendation; a plain count question such as "How many LDAP alerts were there?" gets a clarification asking for the missing time window or configured check. The fixture's LDAP count is 2 alerts in the last 24 hours.

The synthetic seed also includes two read-only review playbooks. Example questions:

- `Investigate authentication review.`
- `Investiga revision de vulnerabilidades.`

Both use a rolling 24-hour window and may be limited by index visibility. Their thresholds refer matching records for manual review; they are not incident verdicts.

REST serves bootstrap, questions, fetches/page, and feedback; MCP serves `soc_ask`, `soc_page`, and `soc_feedback`. Paging is wired but the fixture site issues no cursors, so page requests are refused. The browser UI is not usable locally because it needs an ALB header.

## Documentation

- [Architecture](docs/architecture.md)
- [Domain glossary](CONTEXT.md)
- [Service specification](docs/specification.md)
- [Service and wire contracts](docs/contracts.md)
- [Disaster recovery and live validation runbook](docs/operations/continuity.md)
- [Local offline runners](docs/operations/local-runners.md)
- [Bedrock capability probe](docs/operations/model-probe.md)
- [Telemetry and audit operations](docs/operations/telemetry.md)

## License

MIT. See [LICENSE](LICENSE).

