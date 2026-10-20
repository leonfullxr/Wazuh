# Runnable synthetic external content seed

This fixture can be copied into a separate disposable Git repository and built with the actual `ai-soc-content` CLI. It contains three bilingual topics: LDAP, authentication review, and vulnerability review, reviewed EN/ES routing cues, three English public reference pages, bounded read-only playbooks for the three topics, including authentication-failure and vulnerability-record review over rolling 24-hour windows, a content expectation, a finding template, one L2 topic-card vector, and a solved case marked synthetic.

The source golden at `content/golden/cases/G010.en.doc.json` is an independently authored fixture. Its expected label remains `ldap` for the document-only question. The card vector and embedding manifest are packaging fixtures only: the vector is deliberately synthetic, the manifest names no deployable model, and it is not evidence of semantic model quality or threshold selection. The held-out bilingual quality goldens remain the independent acceptance source.

The public document digest is already populated and checked by the validator. The source manifest records a reserved `example.test` repository and docs origin. No private/customer identifiers, customer data, real endpoint, credential, production query, executable playbook action, or signing key is included.

## Run the offline demonstration

From the service checkout, with the locked environment prepared:

```sh
uv run --locked --offline python examples/content-seed/run_fixture_demo.py \
  --work-dir build/content-fixture-demo
```

Choose a new or empty task-local `build/` directory inside the checkout, outside the tracked seed. The demo copies only this seed into a nested `external-content/` Git repository, creates an ordinary local Git commit with fixed synthetic author/committer metadata, creates a detached `mode=fixture` approval using a fresh in-memory Ed25519 key, and writes only the public trust root plus signed approval. It invokes `ai-soc-content validate`, runs two independent `build` commands against the same commit and attestation, runs `verify` on both packs, byte-compares all outputs, and checks source cleanliness and content/doc provenance. It has no network client or live mode. The ephemeral private key is not written to disk.

The output directory retains the synthetic source, signed approval, public trust root, and two builds for inspection. Remove that disposable directory when finished.

The review playbooks use fixed filters and have no explicit-fetch bindings. Their counts describe matching visible records in the read; row checks describe returned records only. A threshold refers evidence for manual review, not an incident verdict.
