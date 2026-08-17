// Cortex XDR: hourly LOLDrivers BYOVD detection.
// Maintain the Cortex lookup dataset `loldrivers_hashes` with the Ubuntu/API
// synchronizer documented in docs/CORTEX_SERVER_SYNC.md. XQL cannot read
// GitHub URLs with KQL-style externaldata().
// Match only action_module_sha256 so an alert represents a module/driver load.
// File-write and file-access matches are intentionally excluded from this rule.
// In the Correlation Rule UI, set Time Schedule to Hourly and Query Time Frame
// to 1 Hour; the editor does not accept config timeframe in the rule query.
dataset = xdr_data
| filter action_module_sha256 != null
| join conflict_strategy = left type = inner (
    dataset = loldrivers_hashes
    | fields sha256, sha1, md5, driver_name, category, verified, source_id, created
) as lol action_module_sha256 = lol.sha256
| fields _time, agent_hostname, agent_id, agent_os_type, event_type, event_sub_type,
         action_module_sha256,
         action_module_path, action_module_signature_status,
         action_module_signature_vendor, action_module_signature_product,
         event_address_mapped_image_path,
         action_process_image_name, action_process_image_path, driver_name,
         actor_process_image_name, actor_process_image_path,
         actor_process_command_line, actor_process_os_pid,
         actor_primary_username, causality_actor_process_image_name,
         causality_actor_process_image_path, category, verified, source_id, created
