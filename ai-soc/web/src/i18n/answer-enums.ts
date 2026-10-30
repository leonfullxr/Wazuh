import type {
    CheckOutcome,
    JudgmentState,
    LeftOutReason,
    RemovedReason,
    ErrorCode,
} from "../../../contracts/v1/generated/types.ts";

export const reasons: Record<LeftOutReason, [string, string]> = {
    context_exceeded: [
        "The evidence exceeded the model context limit.",
        "La evidencia superó el límite de contexto del modelo.",
    ],
    budget_exceeded: [
        "The question token budget was exhausted.",
        "Se agotó el presupuesto de tokens de la pregunta.",
    ],
    model_unavailable: [
        "The selected model was unavailable.",
        "El modelo seleccionado no estaba disponible.",
    ],
    guardrail_blocked: [
        "The model guardrail blocked this judgment.",
        "La protección del modelo bloqueó este juicio.",
    ],
    invalid_output: [
        "The model response could not be validated.",
        "No se pudo validar la respuesta del modelo.",
    ],
    all_removed: [
        "Validation removed every proposed finding.",
        "La validación eliminó todos los hallazgos propuestos.",
    ],
    token_count_unavailable: [
        "The service could not count model tokens.",
        "El servicio no pudo contar los tokens del modelo.",
    ],
    deadline_exceeded: [
        "The request deadline was reached.",
        "Se alcanzó el plazo límite de la solicitud.",
    ],
    capacity_limited: [
        "Service capacity limited this stage.",
        "La capacidad del servicio limitó esta etapa.",
    ],
    evidence_unavailable: [
        "Required evidence was unavailable.",
        "La evidencia necesaria no estaba disponible.",
    ],
};
export const judgments: Record<JudgmentState, [string, string]> = {
    not_requested: ["Not requested", "No solicitado"],
    validated: ["Validated", "Validado"],
    denial: ["Denied", "Denegado"],
    ingestion_unconfirmed: ["Ingestion unconfirmed", "Ingesta sin confirmar"],
    context_exceeded: ["Context exceeded", "Contexto excedido"],
    budget_exceeded: ["Budget exceeded", "Presupuesto excedido"],
    model_unavailable: ["Model unavailable", "Modelo no disponible"],
    guardrail_blocked: ["Guardrail blocked", "Bloqueado por protección"],
    invalid_output: ["Invalid output", "Respuesta no válida"],
    no_findings: ["No findings", "Sin hallazgos"],
    all_removed: ["All findings removed", "Se eliminaron todos"],
    evidence_unavailable: ["Evidence unavailable", "Evidencia no disponible"],
    token_count_unavailable: ["Token count unavailable", "Conteo de tokens no disponible"],
    deadline_exceeded: ["Deadline exceeded", "Plazo excedido"],
    capacity_limited: ["Capacity limited", "Capacidad limitada"],
};
export const removed: Record<RemovedReason, [string, string]> = {
    unknown_evidence: ["Unknown evidence", "Evidencia desconocida"],
    cross_topic: ["Evidence from another topic", "Evidencia de otro tema"],
    bad_binding: ["Value did not match evidence", "El valor no coincide con la evidencia"],
    unsupported_value: ["Value was not supported", "Valor sin respaldo"],
    unknown_template: ["Unknown template", "Plantilla desconocida"],
    invalid_schema: ["Invalid structure", "Estructura no válida"],
    bad_relation: ["Invalid evidence relation", "Relación de evidencia no válida"],
    failed_prerequisite: ["Required check did not pass", "No se superó una comprobación necesaria"],
    duplicate_id: ["Duplicate finding", "Hallazgo duplicado"],
};
export const outcomes: Record<CheckOutcome, [string, string]> = {
    passed: ["Passed", "Superada"],
    failed: ["Failed", "Fallida"],
    unknown: ["Unknown", "Desconocida"],
    denied: ["Denied", "Denegada"],
    not_configured: ["Not configured", "No configurada"],
};
export const errorCopy: Record<ErrorCode, [string, string]> = {
    BAD_REQUEST: ["The request is invalid.", "La solicitud no es válida."],
    UNAUTHENTICATED: ["Sign in is required.", "Se requiere iniciar sesión."],
    AUTH_REQUIRED: ["Authentication is required.", "Se requiere autenticación."],
    AUTH_INVALID: [
        "Authentication could not be verified.",
        "No se pudo verificar la autenticación.",
    ],
    AUTH_EXPIRED: [
        "Your session expired. Refresh and try again.",
        "La sesión caducó. Actualiza e inténtalo de nuevo.",
    ],
    FORBIDDEN: ["This action is not allowed.", "Esta acción no está permitida."],
    SITE_DENIED: ["You do not have access to this site.", "No tienes acceso a este sitio."],
    ORIGIN_DENIED: [
        "This page origin is not allowed.",
        "El origen de esta página no está permitido.",
    ],
    CSRF_DENIED: [
        "The request could not pass browser security checks. Refresh and try again.",
        "La solicitud no superó las comprobaciones de seguridad. Actualiza e inténtalo de nuevo.",
    ],
    SCOPE_DENIED: [
        "This request is outside the permitted scope.",
        "La solicitud está fuera del alcance permitido.",
    ],
    FOLLOWUP_EXPIRED: [
        "This follow-up has expired. Ask the question again.",
        "Este seguimiento caducó. Vuelve a preguntar.",
    ],
    FOLLOWUP_CONFLICT: [
        "The follow-up changed. Ask the question again.",
        "El seguimiento cambió. Vuelve a preguntar.",
    ],
    QUESTION_ACTIVE: ["This question is already running.", "Esta pregunta ya está en curso."],
    IDEMPOTENCY_CONFLICT: [
        "This request key was already used for another request.",
        "Esta clave ya se usó en otra solicitud.",
    ],
    POLICY_CHANGED: [
        "Site policy changed. Ask again to use current policy.",
        "La política del sitio cambió. Vuelve a preguntar.",
    ],
    CONTENT_CHANGED: [
        "Reviewed content changed. Ask again.",
        "El contenido revisado cambió. Vuelve a preguntar.",
    ],
    BUSY: [
        "The service is busy. Try again shortly.",
        "El servicio está ocupado. Inténtalo pronto.",
    ],
    RATE_LIMITED: ["The request limit was reached.", "Se alcanzó el límite de solicitudes."],
    UNSUPPORTED_MODEL: ["That model is not available.", "Ese modelo no está disponible."],
    UNSUPPORTED_EFFORT: [
        "That effort is not available for this model.",
        "Ese nivel no está disponible para este modelo.",
    ],
    INVALID_WINDOW: [
        "The requested time window is invalid.",
        "El intervalo solicitado no es válido.",
    ],
    INVALID_FILTER: [
        "The request contains an unsupported filter.",
        "La solicitud contiene un filtro no compatible.",
    ],
    INVALID_SCHEMA: ["The request format is invalid.", "El formato de la solicitud no es válido."],
    DEPENDENCY_UNAVAILABLE: [
        "A required service is unavailable.",
        "Un servicio necesario no está disponible.",
    ],
    SERVICE_DISABLED: ["The service is disabled.", "El servicio está desactivado."],
    CONFIG_INVALID: [
        "The service configuration is invalid.",
        "La configuración del servicio no es válida.",
    ],
    INTERNAL: [
        "The service could not complete the request.",
        "El servicio no pudo completar la solicitud.",
    ],
    INDEXER_AUTH_REJECTED: [
        "The index service rejected authentication.",
        "El servicio de índices rechazó la autenticación.",
    ],
    INDEXER_DENIED: [
        "The index service denied access.",
        "El servicio de índices denegó el acceso.",
    ],
    INDEXER_UNAVAILABLE: [
        "The index service is unavailable.",
        "El servicio de índices no está disponible.",
    ],
    MAPPING_UNSUPPORTED: [
        "The index mapping is unsupported.",
        "El mapeo del índice no es compatible.",
    ],
    QUERY_INVALID: [
        "The reviewed query could not be run.",
        "No se pudo ejecutar la consulta revisada.",
    ],
    CA_UNTRUSTED: [
        "The index service certificate is not trusted.",
        "El certificado del servicio de índices no es de confianza.",
    ],
    TOKEN_BROKER_UNAVAILABLE: [
        "The identity service is unavailable.",
        "El servicio de identidad no está disponible.",
    ],
    CONTEXT_EXCEEDED: [
        "The model context limit was reached.",
        "Se alcanzó el límite de contexto del modelo.",
    ],
    TOKEN_COUNT_UNAVAILABLE: [
        "Token counting is unavailable.",
        "El conteo de tokens no está disponible.",
    ],
    BUDGET_EXCEEDED: [
        "The question budget was reached.",
        "Se alcanzó el presupuesto de la pregunta.",
    ],
    MODEL_UNAVAILABLE: ["The model is unavailable.", "El modelo no está disponible."],
    GUARDRAIL_BLOCKED: [
        "The model guardrail blocked the request.",
        "La protección del modelo bloqueó la solicitud.",
    ],
    INVALID_MODEL_OUTPUT: [
        "The model response could not be validated.",
        "No se pudo validar la respuesta del modelo.",
    ],
    CONTENT_INVALID: [
        "Reviewed content could not be loaded.",
        "No se pudo cargar el contenido revisado.",
    ],
    LEASE_LOST: [
        "The service could not confirm completion.",
        "El servicio no pudo confirmar la finalización.",
    ],
    FEEDBACK_UNAVAILABLE: [
        "Feedback could not be queued.",
        "No se pudo poner los comentarios en cola.",
    ],
    FEEDBACK_INVALID: [
        "The feedback request is invalid.",
        "La solicitud de comentarios no es válida.",
    ],
    EVIDENCE_INVALID: ["Evidence could not be validated.", "No se pudo validar la evidencia."],
    EVIDENCE_LIMIT: ["The evidence limit was reached.", "Se alcanzó el límite de evidencia."],
    CAPACITY_LIMIT: ["Service capacity was reached.", "Se alcanzó la capacidad del servicio."],
    DEADLINE_EXCEEDED: ["The request took too long.", "La solicitud tardó demasiado."],
    AUDIT_UNAVAILABLE: [
        "The answer was not published because its audit record could not be stored.",
        "La respuesta no se publicó porque no se pudo guardar su registro de auditoría.",
    ],
    REQUEST_COMPLETED: ["This request already completed.", "Esta solicitud ya se completó."],
    REQUEST_ABANDONED: ["This request was abandoned.", "Se abandonó esta solicitud."],
    INVALID_CONTINUATION: ["That topic cannot be continued.", "No se puede continuar ese tema."],
    REQUEST_TOO_LARGE: ["The request is too large.", "La solicitud es demasiado grande."],
    REQUEST_COMPLEXITY: [
        "The request contains too much scope.",
        "La solicitud contiene demasiado alcance.",
    ],
    CURSOR_EXPIRED: [
        "Results expired. Ask again.",
        "Los resultados caducaron. Vuelve a preguntar.",
    ],
    INVALID_MODEL_SELECTION: [
        "Choose a supported model and effort.",
        "Elige un modelo y esfuerzo compatibles.",
    ],
};
