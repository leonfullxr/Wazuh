export function validateNarrativeReadResponse(
  data: unknown,
): data is components["schemas"]["NarrativeReadResponse"];
export function validateChainPage(data: unknown): data is components["schemas"]["ChainPage"];
export function validateChainCandidateDetail(
  data: unknown,
): data is components["schemas"]["ChainCandidateDetail"];
export function validateChainDismissResponse(
  data: unknown,
): data is components["schemas"]["ChainDismissResponse"];
export function validateIncidentPage(data: unknown): data is components["schemas"]["IncidentPage"];
export function validateIncidentActionResponse(
  data: unknown,
): data is components["schemas"]["IncidentActionResponse"];
export function validateIncidentDetailResponse(
  data: unknown,
): data is components["schemas"]["IncidentDetailResponse"];
export function validateIncidentEventsResponse(
  data: unknown,
): data is components["schemas"]["IncidentEventsResponse"];
export function validateIncidentContextResponse(
  data: unknown,
): data is components["schemas"]["IncidentContextResponse"];
export function validateIncidentCommentDTO(
  data: unknown,
): data is components["schemas"]["IncidentCommentDTO"];
export function validateIncidentDispositionDTO(
  data: unknown,
): data is components["schemas"]["IncidentDispositionDTO"];
import type { components } from "../../../contracts/workspace/v1/types.ts";
export function validateAlertDetail(data: unknown): data is components["schemas"]["AlertDetail"];
export function validateAlertContext(
  data: unknown,
): data is components["schemas"]["GroupContextResponse"];
export function validateAlertPage(
  data: unknown,
): data is components["schemas"]["Page_AlertSummary_"];
export function validateWorkspaceError(
  data: unknown,
): data is components["schemas"]["ErrorResponse"];
export function validateIngestionHealth(
  data: unknown,
): data is components["schemas"]["IngestionHealthResponse"];
export function validateOverview(data: unknown): data is components["schemas"]["OverviewResponse"];
export function validateSitePage(data: unknown): data is components["schemas"]["Page_SiteSummary_"];
export function validateQueuePage(
  data: unknown,
): data is components["schemas"]["Page_QueueSummary_"];
export function validateGroupDetail(data: unknown): data is components["schemas"]["GroupDetail"];
export function validateWorkState(data: unknown): data is components["schemas"]["WorkState"];
export function validateDisposition(data: unknown): data is components["schemas"]["Disposition"];
export function validateBulkActionResponse(
  data: unknown,
): data is components["schemas"]["BulkActionResponse"];
export function validateAssetPage(data: unknown): data is components["schemas"]["Page_AssetTag_"];
export function validateAssetTag(data: unknown): data is components["schemas"]["AssetTag"];
export function validateOpsMetrics(
  data: unknown,
): data is components["schemas"]["OpsMetricsResponse"];
export function validateQualityMetrics(
  data: unknown,
): data is components["schemas"]["QualityMetricsResponse"];
export function validateAssignRequest(
  data: unknown,
): data is components["schemas"]["AssignRequest"];
export function validateStatusRequest(
  data: unknown,
): data is components["schemas"]["StatusRequest"];
export function validateDispositionRequest(
  data: unknown,
): data is components["schemas"]["DispositionRequest"];
export function validateBulkActionRequest(
  data: unknown,
): data is components["schemas"]["BulkActionRequest"];
export function validateAssetUpsertRequest(
  data: unknown,
): data is components["schemas"]["AssetTagUpsertRequest"];
