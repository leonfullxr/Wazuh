import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Eye, EyeOff, FileKey2, KeyRound, RefreshCw, ShieldCheck } from "lucide-react";
import {
    getLocalRuntime,
    localSessionExpiredEvent,
    LocalSessionError,
    signInLocal,
    type LocalSession,
} from "../../api/local-session";
import { ThemeMenu } from "../../components/theme/theme-menu";
import { initialLocale, saveLocale, type Locale } from "../../i18n";
import "./local-session.css";

type BoundaryState =
    | { kind: "checking" }
    | { kind: "public" }
    | { kind: "error" }
    | { kind: "signed-out"; reason: "required" | "expired"; modelEnabled: boolean }
    | { kind: "signed-in"; session: LocalSession };

const copy = {
    en: {
        eyebrow: "Private local console",
        title: "Enter your AI SOC workspace",
        description:
            "Use the private access key issued when this local instance started. It is exchanged for a secure session cookie.",
        choose: "Choose access key file",
        chosen: "Key loaded from",
        divider: "or paste the key",
        label: "Local access key",
        helper: "Choose runtime/sign-in.key under the state directory. The key is never added to the page URL or browser storage.",
        show: "Show access key",
        hide: "Hide access key",
        submit: "Enter workspace",
        submitting: "Checking key…",
        invalid: "That access key was not accepted. Check the file or paste the current key.",
        unavailable:
            "The local console could not verify this session. Check the service and try again.",
        fileError: "That file could not be read. Choose the text key created by local setup.",
        expired: "Your local session expired. Enter the access key again to continue.",
        checking: "Checking local session…",
        retry: "Try again",
        protected: "Same-origin session",
        indexer: "Wazuh Indexer access remains server-side",
        appearance: "Appearance",
        language: "Language",
    },
    es: {
        eyebrow: "Consola local privada",
        title: "Entra en tu espacio de AI SOC",
        description:
            "Usa la clave privada emitida al iniciar esta instancia local. Se cambia por una cookie de sesión segura.",
        choose: "Elegir archivo de clave",
        chosen: "Clave cargada desde",
        divider: "o pega la clave",
        label: "Clave de acceso local",
        helper: "Elige runtime/sign-in.key dentro del directorio de estado. La clave nunca se añade a la URL ni al almacenamiento del navegador.",
        show: "Mostrar clave de acceso",
        hide: "Ocultar clave de acceso",
        submit: "Entrar al espacio",
        submitting: "Comprobando clave…",
        invalid: "La clave no ha sido aceptada. Comprueba el archivo o pega la clave actual.",
        unavailable:
            "La consola local no pudo verificar la sesión. Comprueba el servicio e inténtalo de nuevo.",
        fileError:
            "No se pudo leer el archivo. Elige la clave de texto creada durante la configuración.",
        expired: "Tu sesión local ha caducado. Introduce de nuevo la clave para continuar.",
        checking: "Comprobando la sesión local…",
        retry: "Reintentar",
        protected: "Sesión del mismo origen",
        indexer: "El acceso al Indexer de Wazuh permanece en el servidor",
        appearance: "Apariencia",
        language: "Idioma",
    },
} satisfies Record<Locale, Record<string, string>>;

export function LocalSessionBoundary({
    children,
}: {
    children: (session: LocalSession | null) => ReactNode;
}) {
    const queryClient = useQueryClient();
    const [state, setState] = useState<BoundaryState>({ kind: "checking" });
    const authenticated = useRef(false);

    async function checkSession(signal?: AbortSignal) {
        try {
            const runtime = await getLocalRuntime(signal);
            if (runtime.kind === "not-local") {
                authenticated.current = false;
                setState({ kind: "public" });
                return;
            }
            if (runtime.session.authenticated) {
                authenticated.current = true;
                setState({ kind: "signed-in", session: runtime.session });
                return;
            }
            const reason = authenticated.current ? "expired" : "required";
            authenticated.current = false;
            queryClient.clear();
            setState({
                kind: "signed-out",
                reason,
                modelEnabled: runtime.session.modelEnabled,
            });
        } catch (error) {
            if (error instanceof DOMException && error.name === "AbortError") return;
            setState({ kind: "error" });
        }
    }

    useEffect(() => {
        const controller = new AbortController();
        void checkSession(controller.signal);
        return () => controller.abort();
    }, []);

    useEffect(() => {
        if (state.kind !== "signed-in") return;
        const onFocus = () => void checkSession();
        const timer = window.setInterval(() => void checkSession(), 30_000);
        window.addEventListener("focus", onFocus);
        window.addEventListener(localSessionExpiredEvent, onFocus);
        return () => {
            window.clearInterval(timer);
            window.removeEventListener("focus", onFocus);
            window.removeEventListener(localSessionExpiredEvent, onFocus);
        };
    }, [state.kind]);

    if (state.kind === "public") return children(null);
    if (state.kind === "signed-in") return children(state.session);
    if (state.kind === "checking") return <LocalSessionLoading />;
    if (state.kind === "error") return <LocalSessionFailure onRetry={() => void checkSession()} />;
    return (
        <LocalSignIn
            reason={state.reason}
            onSignedIn={async (key, signal) => {
                await signInLocal(key, signal);
                await checkSession(signal);
            }}
        />
    );
}

function LocalSessionLoading() {
    const locale = initialLocale();
    return (
        <main className="local-session-state" aria-busy="true">
            <span className="local-session-spinner" aria-hidden="true" />
            <p role="status">{copy[locale].checking}</p>
        </main>
    );
}

function LocalSessionFailure({ onRetry }: { onRetry: () => void }) {
    const locale = initialLocale();
    const words = copy[locale];
    return (
        <main className="local-session-state">
            <div className="local-session-state-icon">
                <RefreshCw size={20} aria-hidden="true" />
            </div>
            <h1>{words.unavailable}</h1>
            <button className="btn primary" type="button" onClick={onRetry}>
                {words.retry}
            </button>
        </main>
    );
}

function LocalSignIn({
    reason,
    onSignedIn,
}: {
    reason: "required" | "expired";
    onSignedIn: (key: string, signal: AbortSignal) => Promise<void>;
}) {
    const [locale, setLocale] = useState<Locale>(() => initialLocale());
    const [key, setKey] = useState("");
    const [fileName, setFileName] = useState("");
    const [showKey, setShowKey] = useState(false);
    const [pending, setPending] = useState(false);
    const [error, setError] = useState("");
    const inputRef = useRef<HTMLInputElement>(null);
    const controllerRef = useRef<AbortController | null>(null);
    const words = copy[locale];

    useEffect(() => {
        document.documentElement.lang = locale;
        document.title = `AI SOC | ${words.title}`;
        saveLocale(locale);
    }, [locale, words.title]);

    useEffect(() => () => controllerRef.current?.abort(), []);

    async function readKeyFile(file: File | undefined) {
        if (!file) return;
        setError("");
        try {
            if (file.size > 512) throw new Error("key file too large");
            const value = (await file.text()).trim();
            if (!value) throw new Error("empty key file");
            setKey(value);
            setFileName(file.name);
            requestAnimationFrame(() => inputRef.current?.focus());
        } catch {
            setKey("");
            setFileName("");
            setError(words.fileError);
        }
    }

    async function submit(event: FormEvent<HTMLFormElement>) {
        event.preventDefault();
        const trimmedKey = key.trim();
        if (!trimmedKey) {
            inputRef.current?.focus();
            return;
        }
        const controller = new AbortController();
        controllerRef.current = controller;
        setPending(true);
        setError("");
        try {
            await onSignedIn(trimmedKey, controller.signal);
            setKey("");
        } catch (failure) {
            if (failure instanceof DOMException && failure.name === "AbortError") return;
            setError(
                failure instanceof LocalSessionError && failure.kind === "invalid-key"
                    ? words.invalid
                    : words.unavailable,
            );
            inputRef.current?.focus();
        } finally {
            setPending(false);
            controllerRef.current = null;
        }
    }

    return (
        <main className="local-login">
            <div className="local-login-toolbar">
                <label>
                    <span className="sr-only">{words.language}</span>
                    <select
                        value={locale}
                        aria-label={words.language}
                        onChange={(event) => setLocale(event.target.value === "es" ? "es" : "en")}
                    >
                        <option value="en">EN</option>
                        <option value="es">ES</option>
                    </select>
                </label>
                <ThemeMenu locale={locale} />
            </div>
            <section className="local-login-card" aria-labelledby="local-login-title">
                <div className="local-login-intro">
                    <div className="local-login-brand">
                        <span className="brand-mark">
                            <ShieldCheck size={18} aria-hidden="true" />
                        </span>
                        <span>Wazuh AI SOC</span>
                    </div>
                    <p className="local-login-eyebrow">{words.eyebrow}</p>
                    <h1 id="local-login-title">{words.title}</h1>
                    <p>{words.description}</p>
                    <ul className="local-login-assurances">
                        <li>
                            <KeyRound size={15} aria-hidden="true" /> {words.protected}
                        </li>
                        <li>
                            <ShieldCheck size={15} aria-hidden="true" /> {words.indexer}
                        </li>
                    </ul>
                </div>
                <form
                    className="local-login-form"
                    action="/v1/local/session"
                    method="post"
                    onSubmit={submit}
                >
                    {reason === "expired" && (
                        <div className="local-login-notice" role="alert">
                            {words.expired}
                        </div>
                    )}
                    <label className="local-key-file">
                        <FileKey2 size={18} aria-hidden="true" />
                        <span>{words.choose}</span>
                        <input
                            type="file"
                            name="access-key-file"
                            accept=".txt,text/plain"
                            onChange={(event) => {
                                const file = event.currentTarget.files?.[0];
                                event.currentTarget.value = "";
                                void readKeyFile(file);
                            }}
                        />
                    </label>
                    {fileName && (
                        <p className="local-key-loaded" role="status">
                            {words.chosen} <strong>{fileName}</strong>
                        </p>
                    )}
                    <div className="local-login-divider">
                        <span>{words.divider}</span>
                    </div>
                    <div className="local-key-field">
                        <label htmlFor="local-access-key">{words.label}</label>
                        <div className="local-key-input">
                            <input
                                ref={inputRef}
                                id="local-access-key"
                                name="key"
                                type={showKey ? "text" : "password"}
                                value={key}
                                onChange={(event) => {
                                    setKey(event.target.value);
                                    if (error) setError("");
                                }}
                                autoComplete="current-password"
                                enterKeyHint="done"
                                spellCheck={false}
                                autoCorrect="off"
                                autoCapitalize="none"
                                aria-describedby="local-key-help local-key-error"
                                aria-invalid={error ? "true" : undefined}
                                required
                            />
                            <button
                                type="button"
                                aria-pressed={showKey}
                                aria-label={showKey ? words.hide : words.show}
                                title={showKey ? words.hide : words.show}
                                onClick={() => setShowKey((visible) => !visible)}
                            >
                                {showKey ? <EyeOff size={17} /> : <Eye size={17} />}
                            </button>
                        </div>
                        <p id="local-key-help">{words.helper}</p>
                        <p id="local-key-error" className="local-key-error" aria-live="polite">
                            {error}
                        </p>
                    </div>
                    <button className="local-login-submit" type="submit" disabled={pending}>
                        {pending ? words.submitting : words.submit}
                    </button>
                </form>
            </section>
        </main>
    );
}
