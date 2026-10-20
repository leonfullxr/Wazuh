locals {
  evidence_paths = {
    app_prefix                   = "qualification/"
    consumer_prefix              = "events/qualification/"
    map_key                      = "qualification-maps/resource-map.json"
    input_prefix                 = "qualification-inputs/"
    production_consumer_prefixes = toset(["events/", "feedback/"])
  }
  audit_archive_object_prefixes = setunion(
    local.evidence_paths.production_consumer_prefixes,
    toset([
      local.evidence_paths.app_prefix,
      local.evidence_paths.consumer_prefix,
      local.evidence_paths.map_key,
      local.evidence_paths.input_prefix,
    ])
  )
  audit_archive_list_prefixes = local.audit_archive_object_prefixes
}
