import "@fontsource-variable/inter/opsz.css";
import "@fontsource-variable/manrope/index.css";
import "@fontsource/jetbrains-mono/400.css";
import "@fontsource/jetbrains-mono/500.css";
import "./styles/tokens.css";
import "./styles/global.css";
import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { App } from "./app/App";
import { applyInitialTheme } from "./components/theme/theme-menu";

const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
applyInitialTheme();
ReactDOM.createRoot(document.getElementById("root")!).render(
    <React.StrictMode>
        <QueryClientProvider client={queryClient}>
            <App />
        </QueryClientProvider>
    </React.StrictMode>,
);
