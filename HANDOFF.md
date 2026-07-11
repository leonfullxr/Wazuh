# Handoff: Obsidian vault → Wazuh knowledge-base repo

**For the next LLM session.** Work from this repository (`knowledge-base` branch).  
**Do not touch:** `integrations/ai-assistant/` code changes (unrelated WIP), `wazuh-ai/` in Obsidian.

---

## 1. Goal

Turn personal support notes into a **public, production-grade knowledge base**: troubleshooting runbooks, configuration guides, and verified scripts. The repo should read like official operational documentation, not raw ticket dumps.

**Quality bar:** Each published file should justify its existence (depth, tested commands, clear when-to-use). Thin stubs should be **merged**, **expanded**, or **dropped**.

---

## 2. Two sources

| Source | Path (from repo root) | Role |
|--------|------------------------|------|
| **This repo** | `.` | Curated, shareable KB (target) |
| **Obsidian vault** | `../../Notes/Obsidian/Wazuh/` | Working notebook; ~107 enriched notes; JIRA refs; wikilinks |
| **Mapping doc** | `SYNC_MAPPING.md` | Obsidian filename ↔ repo path |
| **Stale branch** | `kb-enrichment` (5 commits) | Partially cherry-picked; do not merge wholesale |

**Sync direction:** Obsidian → repo when content is stable. Repo is often **already richer** for core ops (agents, indexer, cloud SaaS). Obsidian has **~25 integration topics** with no repo home yet.

---

## 3. What was completed (Obsidian vault)

Seven folder-scoped enrichment passes on `../../Notes/Obsidian/Wazuh/` (skipped `wazuh-ai/`, `_archive/` used for merge-only):

- **integrations/** (35 files) - structured H2s, anonymized secrets/IPs, `## Related` wikilinks
- **troubleshooting/indexer/** (15) - major rewrite of `CCS configuration.md` (612→~318 lines; stripped JIRA comment threads)
- **troubleshooting/** root + cloud + server (21) - `SSL - certificates.md` 717→278 lines; `DR.md` cleaned
- **scripts/** + **upgrading/** (18) - Purpose/Prerequisites/Usage structure; DR + symlink content merged into Deployment / Before-Upgrading
- **kubernetes/** (7) - consistent sections; archive backup/storage refs
- **decoders/** + **docker/** + **configurations/** + **rules/** (8)
- MOC hubs updated (`Wazuh Home.md`, `MOC - *`)

**Obsidian conventions kept:** JIRA URLs at top of notes; mixed EN/ES per file; customer data anonymized.

---

## 4. What was completed (this repo)

### Already on `knowledge-base` before this session (committed)

Substantial KB built from earlier work (see `git log`):

- `indexer/`, `troubleshooting/`, `upgrading/`, `certificates/`, `cloud/`, `containerization/`, `scripts/` - symptom-driven runbooks, TOCs, tables
- Root `README.md` as index

### This session (mostly **uncommitted**)

**Cherry-picked from `kb-enrichment` into working tree** (via `git checkout kb-enrichment -- <paths>`):

- `upgrading/disaster-recovery.md`
- `containerization/kubernetes/openshift.md`, `persistent-storage.md`
- `containerization/docker/swarm.md`, `backup-and-migration.md`
- `scripts/email-alerting/README.md`, `scripts/active-response/README.md` (+ Python script)
- Expanded `certificates/*`, `upgrading/pre-upgrade-checklist.md`, `upgrading-agents.md`, etc.

**New files created (untracked):**

- `SYNC_MAPPING.md` - vault ↔ repo correlation
- `decoders/syntax.md`, `decoders/fortigate/README.md`, `decoders/vectra/README.md`, `decoders/netIQ/README.md`
- `rules/examples/var.md`
- `upgrading/qa-5.0.md`
- `troubleshooting/agents/windows-registry.md`
- `troubleshooting/disaster-recovery.md` - **stub pointer only** to `upgrading/disaster-recovery.md`

**Updated (uncommitted):** root `README.md`, `upgrading/README.md`, many section READMEs.

**Not committed.** ~81 paths changed; includes unrelated `integrations/ai-assistant/*` Python edits - **exclude from KB commit**.

---

## 5. Known problems (why a second pass is needed)

1. **Too many thin / duplicate files** - e.g. `troubleshooting/disaster-recovery.md` is only a redirect; several new decoder READMEs are minimal; some Obsidian ports lack lab depth.
2. **Personal-note tone** - JIRA-centric, support-thread origin; needs rewriting as standalone runbooks.
3. **Fragmentation** - indexer topics split across `shard-management.md`, `replicas.md`, `ilm-retention.md`, `misc-operations.md` without a single **optimization hub**.
4. **Integration gap** - Obsidian has Bitdefender, IBM, Zabbix, Sealpath, Keycloak, MSSQL, etc.; repo has MISP/Splunk/LDAP/OTX but not those.
5. **Splunk split** - repo `integrations/splunk/README.md` = SOAR hook; Obsidian `Splunk.md` = Logstash forwarding from indexer (different topic).
6. **Broken Obsidian links** - `Wazuh Home.md` references missing notes (`DRI`, meeting notes).
7. **Git hygiene** - stage only KB markdown/scripts; ignore ai-assistant WIP and `images/vagrant/nixOS/`, `sca/rhel/8/roles/` unless intentional.

---

## 6. Recommended target structure (consolidation)

### Per-section pattern

Each top-level folder should have **one authoritative README** that:

- Explains scope in 2-3 paragraphs
- Links to deep-dive docs (not duplicate them)
- Includes a **quick reference table** (symptom → doc, or task → doc)
- Drops or merges files that are <30 lines and add no unique procedure

### Example: `indexer/README.md` (enhancement target)

Current README is good but guides are flat-listed. **Consolidate into:**

1. **README.md** (hub) with:
   - Write path diagram (already present)
   - **Sizing & optimization** section (NEW - synthesize from Obsidian + repo):
     - Recommended shard size (20-40 GB for time-series; alert when active_shards > ~85% limit)
     - Primary shards vs indexer nodes (rule of thumb: &lt;20 shards per GB heap)
     - Replica count (0 for single-node; 1+ for HA; ISM for system indices)
     - ILM/ISM rollover and hot/warm if applicable
     - Links to `shard-management.md`, `replicas.md`, `ilm-retention.md`
   - **Troubleshooting** table (symptom → file)
   - **Advanced** (CCS, GeoIP, reindexing, auditing)

2. **Merge candidates:**
   - `misc-operations.md` snippets → relevant parent docs or README
   - Redundant overlap between `shard-management.md` and Obsidian `Optimizing & troubleshooting.md` → one canonical shard guide

3. **Delete or stub:**
   - Files that only say "see X" without unique content

### Other merge candidates

| Keep | Merge into / delete |
|------|---------------------|
| `upgrading/disaster-recovery.md` | Canonical DR doc |
| `troubleshooting/disaster-recovery.md` | Delete stub OR one line in `troubleshooting/README.md` |
| `certificates/troubleshooting.md` + `component-certificates.md` | Consider single `certificates/README.md` hub + deep dives |
| `cloud/wazuh-cloud-service.md` | Already consolidates 4 Obsidian cloud notes - good pattern |
| Thin decoder READMEs | Expand with deployment + example log + link to XML, or merge into `decoders/README.md` |

---

## 7. Obsidian topics NOT yet in repo (port only if expanded)

Prioritize by ops value; do **not** copy verbatim if thin:

**High value:** Fortinet/syslog ingestion, nginx stream LB, Webhook patterns, MSSQL eventchannel suite, Splunk Logstash forwarding, Ansible (playbook exists at `ansible/rename_wazuh_agents.yaml`)

**Medium:** Bitdefender, Zabbix, Grafana, Keycloak/Jumpcloud SSO, Sophos API, Sealpath/Logstash pipelines

**Low / reference only:** `integrations/AI.md`, `Llama.md`, `New features & integrations.md` - keep in Obsidian or one-line pointer to `integrations/ai-assistant/`

Full list: `SYNC_MAPPING.md` § "Obsidian-only"

---

## 8. Repo topics with NO Obsidian note (keep)

AlienVault OTX, VirusTotal, AbuseIPDB, Confluence/Teams alerting, `scripts/diagnosis/`, `scripts/recovery/`, Docker Traefik/single-node variants, `containerization/kubernetes/wazuh-agent-deployment.md` (official DaemonSet patterns).

---

## 9. Suggested task list for next LLM

### Phase A - Git & hygiene
- [ ] Review `git status`; unstage/revert `integrations/ai-assistant/*` unless user wants those
- [ ] Commit KB changes in logical chunks (certificates, containerization, scripts, decoders, docs)
- [ ] Do **not** force-merge `kb-enrichment`; cherry-picks already applied

### Phase B - Consolidation (repo-only)
- [ ] Audit each section README; add hub tables; remove stub files
- [x] **DR** - merged Obsidian `DR.md` + `kb-enrichment` into `upgrading/disaster-recovery.md`; checklist in `deployment-architecture.md`
- [ ] **indexer/** - build optimization hub in README; merge shard/replica guidance; dedupe `misc-operations.md`
- [ ] **troubleshooting/** - ensure `README.md` quick lookup is complete (add windows-registry, DR link)
- [ ] **certificates/** - single entry point; cross-link SAML, private IP, troubleshooting
- [ ] **integrations/** - add root `integrations/README.md` index (repo + planned); do not create 25 empty folders

### Phase C - Depth pass (Obsidian → repo)
- [ ] For each file to port: rewrite as runbook (Overview → Prerequisites → Procedure → Verification → See also)
- [ ] Strip JIRA blobs; keep ticket IDs in HTML comments only
- [ ] Verify commands; use placeholders (`<MANAGER_IP>`, `example.com`)
- [ ] Skip files that cannot reach production depth after one enrichment pass

### Phase D - Final polish
- [ ] Update root `README.md` to match final structure
- [ ] Update `SYNC_MAPPING.md` with merged/deleted paths
- [ ] User decision pending: standardize EN vs keep ES docs, commit strategy, PR to `main`

---

## 10. Reference paths (from repo root)

```
.
├── README.md                 # Root index
├── SYNC_MAPPING.md           # Vault correlation (untracked)
├── HANDOFF.md                # This file
├── certificates/
├── cloud/
├── containerization/
│   ├── docker/
│   └── kubernetes/
├── indexer/                  # ← priority for optimization hub
├── troubleshooting/
├── upgrading/
├── scripts/                  # One README per subfolder
├── integrations/             # Sparse; many topics only in Obsidian
├── decoders/
└── rules/

Obsidian vault: ../../Notes/Obsidian/Wazuh/
```

---

## 11. User preferences (from prior session)

- Skip `wazuh-ai/` folder entirely
- JIRA links OK at top as internal references
- Anonymize customer names, domains, secrets in public repo
- Mixed EN/ES acceptable unless user asks to standardize
- Structural folders in repo are intentional; prefer README hubs over many tiny files
- Final output should be **worth reading** for someone deploying/troubleshooting Wazuh in production
