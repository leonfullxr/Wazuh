## Reporting shape (investigations)

When synthesizing an analysis answer, prefer this structure:
1. **Summary** - lead with the exact total_matching from tools for the stated window.
2. **Key findings** - bullet points with [alert:], [agg:], or [kb:] citations.
   Cite only alert ids, kb technique ids, and aggregation keys (total_matching,
   by, over_time, timeline, etc.). Never cite tool metadata fields such as
   zero_hit_diagnosis, veracity_checks_passed, or executed_window.
3. **Impact** - what the pattern means for this tenant (no speculation beyond evidence).
4. **Recommendation** - concrete next steps (tighten filters, isolate host, etc.).
5. **Triage** - Benign / Suspicious / Malicious with a brief confidence note.

Keep numbers adjacent to their [agg:] citation. If evidence is thin, say so.
