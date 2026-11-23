import { useEffect, useState } from "react";
import type { DemoSamples } from "../../../verification/samples/redesign";

// The redesigned screens read a few fields the workspace contracts do not carry
// yet (SLA targets and due times, AI verdict vs analyst, entity edges, narrative
// feedback, tuning candidates, dashboard aggregates). The verification build
// supplies sample values so the layout can be reviewed. The live build never
// loads them: MODE is a build-time constant, so the import below is dropped
// and every screen falls back to its "Not reported" state.
export type { DemoSamples };

const load =
    import.meta.env.MODE === "live"
        ? null
        : () => import("../../../verification/samples/redesign").then((module) => module.samples);

let cached: DemoSamples | undefined;

/** `?samples=off` previews the live "Not reported" states in the verification build. */
function samplesOff(): boolean {
    return new URLSearchParams(location.search).get("samples") === "off";
}

export function useSamples(): DemoSamples | undefined {
    const [samples, setSamples] = useState(() => (samplesOff() ? undefined : cached));
    useEffect(() => {
        if (samples || !load || samplesOff()) return;
        let live = true;
        void load().then((value) => {
            cached = value;
            if (live) setSamples(value);
        });
        return () => {
            live = false;
        };
    }, [samples]);
    return samples;
}
