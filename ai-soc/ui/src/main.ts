import type {
  Answer,
  AskRequest,
  BootstrapResponse,
  DomainError,
  FeedbackQueued,
  FeedbackRequest,
  FetchResult,
  PageRequest,
} from "../../contracts/v1/generated/types.js";

type Locale = "en" | "es";

const strings = {
  en: {
    title: "Security investigation",
    askHeading: "Ask a question",
    site: "Site",
    model: "Model",
    defaultModel: "Default",
    effort: "Effort",
    chooseEffort: "Choose",
    question: "Question",
    ask: "Ask SOC",
    cancel: "Cancel",
    working: "Working on your question…",
    cancelled: "Request cancelled.",
    answer: "Answer",
    language: "Language",
    continueHeading: "Continue selected work",
    continueLegend: "Select unfinished topics",
    continue: "Continue selected topics",
    feedback: "Improve this answer",
    note: "Optional note",
    wrong: "This answer is wrong",
    sent: "Feedback sent for human review.",
    loadMore: "Load more rows",
    loading: "Loading…",
    error: "The request could not be completed.",
    noTopics: "No answer blocks were returned.",
    status: (value: string) => `Status: ${value}`,
    missing: "Missing content",
    document: "Open source document",
    retry: "Reload the page to reconnect securely.",
  },
  es: {
    title: "Investigación de seguridad",
    askHeading: "Haz una pregunta",
    site: "Sitio",
    model: "Modelo",
    defaultModel: "Predeterminado",
    effort: "Esfuerzo",
    chooseEffort: "Elegir",
    question: "Pregunta",
    ask: "Preguntar a SOC",
    cancel: "Cancelar",
    working: "Procesando la pregunta…",
    cancelled: "Solicitud cancelada.",
    answer: "Respuesta",
    language: "Idioma",
    continueHeading: "Continuar trabajo seleccionado",
    continueLegend: "Selecciona los temas pendientes",
    continue: "Continuar temas seleccionados",
    feedback: "Mejora esta respuesta",
    note: "Nota opcional",
    wrong: "Esta respuesta es incorrecta",
    sent: "Comentario enviado para revisión humana.",
    loadMore: "Cargar más resultados",
    loading: "Cargando…",
    error: "No se pudo completar la solicitud.",
    noTopics: "No se recibieron bloques de respuesta.",
    status: (value: string) => `Estado: ${value}`,
    missing: "Contenido no disponible",
    document: "Abrir documento de origen",
    retry: "Recarga la página para volver a conectar de forma segura.",
  },
} as const;

const element = <T extends HTMLElement>(id: string): T => {
  const found = document.getElementById(id);
  if (!(found instanceof HTMLElement)) throw new Error(`Missing UI element: ${id}`);
  return found as T;
};

const form = element<HTMLFormElement>("ask-form");
const languageSelect = element<HTMLSelectElement>("language");
const siteSelect = element<HTMLSelectElement>("site");
const modelSelect = element<HTMLSelectElement>("model");
const effortSelect = element<HTMLSelectElement>("effort");
const questionInput = element<HTMLTextAreaElement>("question");
const askButton = element<HTMLButtonElement>("ask-button");
const cancelButton = element<HTMLButtonElement>("cancel-button");
const statusText = element<HTMLParagraphElement>("status");
const answerPanel = element<HTMLElement>("answer-panel");
const answerStatus = element<HTMLParagraphElement>("answer-status");
const answerMessage = element<HTMLParagraphElement>("answer-message");
const answerBlocks = element<HTMLDivElement>("answer-blocks");
const continuation = element<HTMLElement>("continuation");
const continuationList = element<HTMLDivElement>("continuation-list");
const continueButton = element<HTMLButtonElement>("continue-button");
const feedbackButton = element<HTMLButtonElement>("feedback-button");
const feedbackNote = element<HTMLTextAreaElement>("feedback-note");
const feedbackStatus = element<HTMLParagraphElement>("feedback-status");

let locale: Locale = "en";
let bootstrapData: BootstrapResponse | null = null;
let csrfToken = "";
let activeController: AbortController | null = null;
let lastAnswer: Answer | null = null;
let lastQuestion = "";
let selectedEnvironment = "";

function setLocale(next: Locale): void {
  locale = next;
  document.documentElement.lang = locale;
  const copy = strings[locale];
  text("title", copy.title);
  text("question-heading", copy.askHeading);
  text("site-label", copy.site);
  text("model-label", copy.model);
  text("effort-label", copy.effort);
  text("question-label", copy.question);
  text("ask-button", copy.ask);
  text("cancel-button", copy.cancel);
  text("answer-heading", copy.answer);
  text("language-label", copy.language);
  text("continuation-heading", copy.continueHeading);
  text("continuation-legend", copy.continueLegend);
  text("continue-button", copy.continue);
  text("feedback-heading", copy.feedback);
  text("feedback-note-label", copy.note);
  text("feedback-button", copy.wrong);
  text("skip-to-question", locale === "en" ? "Skip to question" : "Ir a la pregunta");
  modelSelect.options[0]!.textContent = copy.defaultModel;
  if (effortSelect.options.length > 0) effortSelect.options[0]!.textContent = copy.chooseEffort;
}

function text(id: string, value: string): void {
  element<HTMLElement>(id).textContent = value;
}

function domainError(value: unknown): DomainError | null {
  if (typeof value !== "object" || value === null || !("code" in value)) return null;
  const code = Reflect.get(value, "code");
  const message = Reflect.get(value, "message");
  if (typeof code !== "string" || typeof message !== "string") return null;
  return value as DomainError;
}

async function api<T>(path: string, body?: object, signal?: AbortSignal, retried = false): Promise<T> {
  const headers = new Headers({ Accept: "application/json" });
  const init: RequestInit = {
    method: body === undefined ? "GET" : "POST",
    headers,
    credentials: "same-origin",
  };
  if (signal) init.signal = signal;
  if (body !== undefined) {
    headers.set("Content-Type", "application/json");
    headers.set("X-SOC-CSRF", csrfToken);
    init.body = JSON.stringify(body);
  }
  const response = await fetch(path, init);
  const result: unknown = await response.json().catch(() => null);
  if (response.status === 403 && !retried && domainError(result)?.code === "CSRF_DENIED") {
    await loadBootstrap();
    return api<T>(path, body, signal, true);
  }
  if (!response.ok) {
    const error = domainError(result);
    throw new Error(error?.message ?? strings[locale].error);
  }
  return result as T;
}

async function loadBootstrap(): Promise<void> {
  bootstrapData = await api<BootstrapResponse>("/v1/bootstrap");
  csrfToken = bootstrapData.csrf_token ?? "";
  siteSelect.replaceChildren();
  for (const site of bootstrapData.sites) {
    const option = document.createElement("option");
    option.value = site.id;
    option.textContent = site.label;
    siteSelect.append(option);
  }
  modelSelect.replaceChildren(new Option(strings[locale].defaultModel, ""));
  for (const model of bootstrapData.models) {
    modelSelect.add(new Option(model.label, model.id));
  }
  syncEffortOptions();
}

function syncEffortOptions(): void {
  const selected = bootstrapData?.models.find((model) => model.id === modelSelect.value);
  effortSelect.replaceChildren(new Option(strings[locale].chooseEffort, ""));
  for (const effort of selected?.efforts ?? []) effortSelect.add(new Option(effort, effort));
  element<HTMLElement>("effort-wrap").hidden = (selected?.efforts.length ?? 0) === 0;
}

function newAsk(question: string, continuationIds?: string[]): AskRequest {
  const selectedModel = modelSelect.value;
  const selectedEffort = effortSelect.value;
  const request: AskRequest = {
    question,
    environment_id: siteSelect.value,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
    language_hint: locale,
  };
  if (selectedModel) request.model_id = selectedModel;
  if (selectedEffort) request.effort = selectedEffort as NonNullable<AskRequest["effort"]>;
  if (lastAnswer?.followup_id && lastAnswer.followup_revision !== undefined && continuationIds) {
    request.followup_id = lastAnswer.followup_id;
    request.followup_revision = lastAnswer.followup_revision;
    request.continue_topic_ids = continuationIds as NonNullable<AskRequest["continue_topic_ids"]>;
  }
  return request;
}

async function submitQuestion(request: AskRequest): Promise<void> {
  if (new TextEncoder().encode(request.question).byteLength > (bootstrapData?.limits.question_bytes ?? 16_384)) {
    statusText.textContent = strings[locale].error;
    return;
  }
  activeController = new AbortController();
  askButton.disabled = true;
  cancelButton.disabled = false;
  statusText.textContent = strings[locale].working;
  try {
    const answer = await api<Answer>("/v1/questions", request, activeController.signal);
    lastAnswer = answer;
    lastQuestion = request.question;
    selectedEnvironment = request.environment_id;
    renderAnswer(answer);
    statusText.textContent = "";
  } catch (error: unknown) {
    if (error instanceof DOMException && error.name === "AbortError") {
      statusText.textContent = strings[locale].cancelled;
    } else {
      statusText.textContent = error instanceof Error ? error.message : strings[locale].error;
    }
  } finally {
    activeController = null;
    askButton.disabled = false;
    cancelButton.disabled = true;
  }
}

function renderAnswer(answer: Answer): void {
  answerPanel.hidden = false;
  answerStatus.textContent = strings[locale].status(answer.status);
  answerMessage.textContent = answer.clarify?.question ?? answer.message ?? "";
  answerBlocks.replaceChildren();
  for (const block of answer.blocks) {
    const section = document.createElement("section");
    section.className = "topic";
    const heading = document.createElement("h3");
    heading.textContent = block.topic_id;
    section.append(heading);
    if (block.document) {
      const pointer = new URL(block.document.url);
      if (pointer.protocol === "https:") {
        const link = document.createElement("a");
        link.href = pointer.toString();
        link.rel = "noopener noreferrer";
        link.textContent = `${block.document.heading} · ${strings[locale].document}`;
        section.append(link);
      }
    }
    if (block.missing.length > 0) {
      const missing = document.createElement("p");
      missing.textContent = `${strings[locale].missing}: ${block.missing.join(", ")}`;
      section.append(missing);
    }
    for (const table of block.tables) {
      const tableSummary = document.createElement("p");
      const count = table.count ? `${table.count.relation === "eq" ? "=" : "≥"}${table.count.value}` : "";
      tableSummary.textContent = `${table.state}${count ? ` · ${count}` : ""}`;
      section.append(tableSummary);
      if (table.message) {
        const tableMessage = document.createElement("p");
        tableMessage.textContent = table.message;
        section.append(tableMessage);
      }
      if (table.next_cursor) {
        const page = document.createElement("button");
        page.type = "button";
        page.className = "secondary";
        page.textContent = strings[locale].loadMore;
        page.addEventListener("click", () => void loadPage(table.next_cursor!, page, section));
        section.append(page);
      }
      appendRows(table.rows.map((row) => row.values), section);
      appendRows(
        (table.buckets ?? []).map((bucket) => ({ bucket: bucket.key, count: bucket.count.value })),
        section,
      );
    }
    for (const check of block.checks) {
      const item = document.createElement("p");
      item.textContent = `${check.label}: ${check.outcome}`;
      section.append(item);
      if (check.message) {
        const checkMessage = document.createElement("p");
        checkMessage.textContent = check.message;
        section.append(checkMessage);
      }
    }
    if (block.judgment.message) {
      const judgmentStatus = document.createElement("p");
      judgmentStatus.textContent = block.judgment.message;
      section.append(judgmentStatus);
    }
    for (const finding of block.judgment.sentences) {
      const item = document.createElement("p");
      item.textContent = finding.text;
      section.append(item);
    }
    answerBlocks.append(section);
  }
  if (answer.blocks.length === 0 && !answer.clarify && !answer.message) {
    const empty = document.createElement("p");
    empty.textContent = strings[locale].noTopics;
    answerBlocks.append(empty);
  }
  renderContinuation(answer);
}

function appendRows(rows: Array<Record<string, unknown>>, parent: HTMLElement): void {
  if (rows.length === 0) return;
  const list = document.createElement("ul");
  for (const row of rows) {
    const item = document.createElement("li");
    item.textContent = Object.entries(row)
      .map(([key, value]) => `${key}: ${typeof value === "string" ? value : JSON.stringify(value)}`)
      .join(" · ");
    list.append(item);
  }
  parent.append(list);
}

async function loadPage(cursor: string, button: HTMLButtonElement, parent: HTMLElement): Promise<void> {
  button.disabled = true;
  button.textContent = strings[locale].loading;
  try {
    const page = await api<FetchResult>("/v1/fetches/page", {
      environment_id: selectedEnvironment,
      cursor,
    } satisfies PageRequest);
    if (page.message) {
      const message = document.createElement("p");
      message.textContent = page.message;
      parent.append(message);
    }
    appendRows(page.rows.map((row) => row.values), parent);
    button.remove();
  } catch (error: unknown) {
    button.disabled = false;
    button.textContent = strings[locale].loadMore;
    statusText.textContent = error instanceof Error ? error.message : strings[locale].error;
  }
}

function renderContinuation(answer: Answer): void {
  continuationList.replaceChildren();
  const eligible = answer.left_out.filter((item) => item.retryable).map((item) => item.topic_id);
  if (!answer.followup_id || eligible.length === 0) {
    continuation.hidden = true;
    return;
  }
  continuation.hidden = false;
  for (const topicId of [...new Set(eligible)]) {
    const label = document.createElement("label");
    label.className = "choice";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.value = topicId;
    checkbox.checked = true;
    const name = document.createElement("span");
    name.textContent = topicId;
    label.append(checkbox, name);
    continuationList.append(label);
  }
}

async function sendFeedback(): Promise<void> {
  if (!lastAnswer) return;
  feedbackButton.disabled = true;
  try {
    const request: FeedbackRequest = {
      question_id: lastAnswer.question_id,
      environment_id: lastAnswer.environment_id,
      feedback_receipt: lastAnswer.feedback_receipt,
      kind: "wrong",
      note: feedbackNote.value || null,
    };
    const queued = await api<FeedbackQueued>("/v1/feedback", request);
    feedbackStatus.textContent = queued.status === "queued" ? strings[locale].sent : strings[locale].error;
  } catch (error: unknown) {
    feedbackStatus.textContent = error instanceof Error ? error.message : strings[locale].error;
  } finally {
    feedbackButton.disabled = false;
  }
}

languageSelect.addEventListener("change", () => setLocale(languageSelect.value as Locale));
modelSelect.addEventListener("change", syncEffortOptions);
siteSelect.addEventListener("change", () => {
  activeController?.abort();
  if (!lastAnswer || lastAnswer.environment_id === siteSelect.value) return;
  lastAnswer = null;
  lastQuestion = "";
  selectedEnvironment = "";
  answerPanel.hidden = true;
  answerStatus.textContent = "";
  answerMessage.textContent = "";
  answerBlocks.replaceChildren();
  continuation.hidden = true;
  continuationList.replaceChildren();
  feedbackStatus.textContent = "";
});
form.addEventListener("submit", (event: SubmitEvent) => {
  event.preventDefault();
  if (activeController) return;
  void submitQuestion(newAsk(questionInput.value));
});
cancelButton.addEventListener("click", () => activeController?.abort());
continueButton.addEventListener("click", () => {
  if (!lastAnswer?.followup_id) return;
  const selected = [...continuationList.querySelectorAll<HTMLInputElement>('input[type="checkbox"]:checked')]
    .map((input) => input.value);
  if (selected.length === 0) {
    statusText.textContent = strings[locale].error;
    return;
  }
  const prefix = locale === "en" ? "Continue the left-out judgments for" : "Continúa los juicios pendientes para";
  void submitQuestion(newAsk(`${prefix} ${selected.join(", ")}`, selected));
});
feedbackButton.addEventListener("click", () => void sendFeedback());

setLocale("en");
void loadBootstrap().catch(() => {
  statusText.textContent = `${strings[locale].error} ${strings[locale].retry}`;
});
