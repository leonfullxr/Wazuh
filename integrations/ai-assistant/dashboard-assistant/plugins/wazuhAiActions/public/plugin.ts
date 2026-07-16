import { CoreSetup, CoreStart, Plugin } from 'opensearch-dashboards/public';

declare global {
  interface Window {
    __wazuhAiActionsInjected?: boolean;
    WAZUH_AI_ACTIONS_CONFIG?: { toolServiceUrl?: string };
  }
}

export class WazuhAiActionsPlugin implements Plugin<Record<string, never>, Record<string, never>> {
  public setup(_core: CoreSetup) {
    return {};
  }

  public start(_core: CoreStart) {
    if (typeof window === 'undefined' || window.__wazuhAiActionsInjected) {
      return {};
    }

    const cfg = window.WAZUH_AI_ACTIONS_CONFIG || {};
    const base = String(cfg.toolServiceUrl || 'http://localhost:8080').replace(/\/$/, '');
    const script = document.createElement('script');
    script.src = `${base}/v1/actions/ui/inject.js`;
    script.async = true;
    script.onerror = () => {
      // eslint-disable-next-line no-console
      console.warn(`wazuhAiActions: failed to load inject.js from ${script.src}`);
    };
    document.head.appendChild(script);
    return {};
  }

  public stop() {}
}
