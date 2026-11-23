// Sample values for fields the workspace contracts do not carry yet. The
// verification build loads this module through src/features/workspace/samples.ts
// so the redesigned layouts can be reviewed. The live build never includes it.

const now = Date.now();
const minutes = (value: number) => new Date(now + value * 60_000).toISOString();

export type SampleSla = { startedAt: string; dueAt: string; metAt?: string | null };
export type SampleEntityKind = "ip" | "host" | "user" | "expected";
export type SampleGraph = {
    nodes: { id: string; kind: SampleEntityKind; label: string; detail: string }[];
    edges: {
        from: string;
        to: string;
        label: string;
        state: "seen" | "expected";
    }[];
};

const incidentId = "33333333-3333-4333-8333-333333333333";

export const samples = {
    triageTargetMinutes: 30,
    slaTargetsSeconds: { acknowledge: 15 * 60, triage: 30 * 60 },
    groupSla: {
        "group-auth-001": { startedAt: minutes(-18), dueAt: minutes(12) },
        "group-sudo-002": { startedAt: minutes(-62), dueAt: minutes(-32), metAt: minutes(-48) },
        "group-score-pending": { startedAt: minutes(-2), dueAt: minutes(28) },
    } as Record<string, SampleSla>,
    incidentSla: {
        [incidentId]: {
            acknowledge: { startedAt: minutes(-50), dueAt: minutes(-35), metAt: minutes(-44) },
            resolve: { startedAt: minutes(-50), dueAt: minutes(430) },
        },
    } as Record<string, { acknowledge: SampleSla; resolve: SampleSla }>,
    incidentSummary: {
        [incidentId]:
            "18 failed SSH logins from 198.51.100.24 to user ops on web-01, then one successful login. A privilege change has not been seen yet.",
    } as Record<string, string>,
    incidentScope: {
        [incidentId]: { hosts: 1, users: 1, ips: 1 },
    } as Record<string, { hosts: number; users: number; ips: number }>,
    entityGraph: {
        [incidentId]: {
            nodes: [
                { id: "ip", kind: "ip", label: "198.51.100.24", detail: "Source IP" },
                { id: "host", kind: "host", label: "web-01", detail: "Agent 003" },
                { id: "user", kind: "user", label: "ops", detail: "User" },
                { id: "next", kind: "expected", label: "sudo by ops", detail: "Expected next" },
            ],
            edges: [
                { from: "ip", to: "host", label: "18 failed logins", state: "seen" },
                { from: "ip", to: "user", label: "1 successful login", state: "seen" },
                { from: "user", to: "next", label: "expected by chain rule", state: "expected" },
            ],
        },
    } as Record<string, SampleGraph>,
    quality: {
        summary: [
            { label: "Questions asked", value: "142", note: "last 7 days" },
            { label: "Topic blocks validated", value: "71%", note: "+4 pts on prior week", tone: "good" },
            { label: "Analyst feedback", value: "81%", note: "helpful, 31 ratings" },
            { label: "Answer time, p50", value: "18 s", note: "p90 41 s" },
        ],
        outcomes: [
            { day: "Tue", answered: 14, partial: 3, clarify: 2, refused: 1 },
            { day: "Wed", answered: 19, partial: 4, clarify: 1, refused: 0 },
            { day: "Thu", answered: 16, partial: 2, clarify: 3, refused: 1 },
            { day: "Fri", answered: 22, partial: 5, clarify: 2, refused: 1 },
            { day: "Sat", answered: 8, partial: 1, clarify: 1, refused: 0 },
            { day: "Sun", answered: 6, partial: 1, clarify: 0, refused: 0 },
            { day: "Mon", answered: 21, partial: 3, clarify: 2, refused: 1 },
        ],
        verdicts: {
            agreement: 0.84,
            compared: 38,
            rows: [
                { verdict: "Likely malicious", agreed: 14, overruled: 2 },
                { verdict: "Suspicious", agreed: 9, overruled: 3 },
                { verdict: "Likely benign", agreed: 9, overruled: 1 },
            ],
        },
        judgment: [
            { label: "Validated", note: "every finding cites evidence", share: 0.71 },
            { label: "Limited", note: "some findings removed", share: 0.15 },
            { label: "No findings", note: "evidence was clean", share: 0.08 },
            { label: "Blocked", note: "budget or validation stop", share: 0.06 },
        ],
        timing: [
            { label: "Retrieval", p50: 4.1, p90: 8.0 },
            { label: "Checks", p50: 1.6, p90: 2.7 },
            { label: "Judgment", p50: 8.8, p90: 13.2 },
            { label: "Validation", p50: 1.9, p90: 3.4 },
            { label: "Audit", p50: 0.6, p90: 1.2 },
        ],
        removals: [
            { label: "Citation not in evidence pack", count: 9 },
            { label: "Claim goes beyond the evidence", count: 6 },
            { label: "Entity not in evidence", count: 3 },
            { label: "Malformed finding", count: 2 },
        ],
        topics: [
            { name: "SSH", questions: 48, validated: 0.82, removals: 4, helpful: 0.88, failure: "Claim goes beyond the evidence" },
            { name: "Sudo and privilege", questions: 31, validated: 0.74, removals: 5, helpful: 0.79, failure: "Citation not in evidence pack" },
            { name: "LDAP", questions: 27, validated: 0.63, removals: 7, helpful: 0.7, failure: "Citation not in evidence pack" },
            { name: "File integrity", questions: 19, validated: 0.58, removals: 4, helpful: 0.75, failure: "Entity not in evidence" },
        ],
        review: [
            { question: "Did any host talk to 198.51.100.24 after 09:14?", meta: "SSH · analyst:demo · Mon 10:42", reason: "Rated not helpful", tone: "red" },
            { question: "Which users ran sudo on auth-02 today?", meta: "Sudo and privilege · analyst:maria · Mon 09:05", reason: "3 findings removed", tone: "amber" },
            { question: "Summarise LDAP binds from the DMZ", meta: "LDAP · analyst:demo · Fri 16:20", reason: "Blocked by budget", tone: "neutral" },
        ],
    },
    operations: {
        summary: [
            { label: "Groups opened", value: "64", note: "last 7 days" },
            { label: "Groups closed", value: "58", note: "91% of opened" },
            { label: "Open backlog", value: "23", note: "+6 this week", tone: "warn" },
            { label: "Unassigned", value: "7", note: "2 near SLA", tone: "warn" },
        ],
        sla: [
            { label: "Time to acknowledge", target: "15 min", p50: "9 min", p90: "31 min", within: 0.88, withinText: "88% within target", missed: 7 },
            { label: "Time to triage", target: "30 min", p50: "21 min", p90: "52 min", within: 0.84, withinText: "84% within target", missed: 10 },
            { label: "Incident resolution", target: "8 h", p50: "3 h 40 min", p90: "7 h 10 min", within: 1, withinText: "3 of 3 within target", missed: 0 },
        ],
        flow: [
            { day: "Tue", opened: 9, closed: 8 },
            { day: "Wed", opened: 14, closed: 9 },
            { day: "Thu", opened: 11, closed: 10 },
            { day: "Fri", opened: 10, closed: 12 },
            { day: "Sat", opened: 4, closed: 3 },
            { day: "Sun", opened: 3, closed: 2 },
            { day: "Mon", opened: 13, closed: 14 },
        ],
        funnel: [
            { label: "Alerts ingested", count: 312 },
            { label: "Grouped into", count: 64 },
            { label: "Triaged", count: 61 },
            { label: "True positive", count: 18 },
            { label: "Became incidents", count: 3 },
        ],
        age: [
            { label: "Under 1 h", levels: [1, 2, 2, 1] },
            { label: "1 to 4 h", levels: [1, 3, 2, 2] },
            { label: "4 to 24 h", levels: [0, 2, 2, 1] },
            { label: "1 to 3 days", levels: [0, 1, 1, 1] },
            { label: "Over 3 days", levels: [0, 0, 0, 1] },
        ],
        load: [
            { name: "analyst:maria", open: 9, actions: 74, p50: "18 min", missed: 3 },
            { name: "analyst:demo", open: 7, actions: 61, p50: "24 min", missed: 5 },
            { name: "Unassigned", open: 7, actions: null, p50: null, missed: 2 },
        ],
        tuning: [
            { name: "Multiple authentication failures", rule: "5712", host: "web-01", closed: 14, total: 17, reason: "Known scanner or test host" },
            { name: "Login session opened", rule: "5501", host: "auth-02", closed: 22, total: 24, reason: "Expected admin or service activity" },
            { name: "Sudo command executed", rule: "31151", host: "auth-02", closed: 6, total: 11, reason: "Expected admin or service activity" },
        ],
    },
};

export type DemoSamples = typeof samples;
