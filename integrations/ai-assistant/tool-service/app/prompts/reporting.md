## Reporting shapes (D56)

When a shape instruction is injected for this turn, follow that shape's
headings exactly. Otherwise, for investigation-style analysis prefer:

1. **Summary** - lead with the exact total_matching from tools for the stated window.
2. **Key findings** - bullet points with [alert:], [agg:], or [kb:] citations.
   Cite only alert ids, kb technique ids, and aggregation keys (total_matching,
   by, over_time, timeline, delta, etc.). Never cite tool metadata fields such as
   zero_hit_diagnosis, veracity_checks_passed, or executed_window.
3. **Impact** - what the pattern means for this tenant (no speculation beyond evidence).
4. **Recommendation** - concrete next steps (tighten filters, isolate host, etc.).
5. **Triage** - Benign / Suspicious / Malicious with a brief confidence note.

Keep numbers adjacent to their [agg:] citation. If evidence is thin, say so.

Named shapes (selected server-side and injected as transient context):
- **triage_card** - Summary / Evidence / Impact / Recommendation / Triage
- **incident_summary** - What happened / Scope / Timeline / Next steps
- **exec_rollup** - Headline / Numbers / Risk posture / Ask of leadership
