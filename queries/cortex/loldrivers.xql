// Cortex XDR: hourly known vulnerable driver detection.
// Keep the `loldrivers_hashes` lookup current before enabling the rule.
// Configure the schedule and query time frame in the Scheduled Correlation
// Rule editor; do not add `config timeframe` to this query.
dataset = xdr_data
| filter action_module_sha256 != null
| fields _time, agent_hostname, agent_id, event_type, event_sub_type,
         action_module_sha256, action_module_path, action_module_is_replay,
         action_module_file_info, action_module_signature_status,
         action_module_signature_vendor, action_module_signature_product,
         actor_process_image_name, actor_process_image_path, actor_process_command_line,
         actor_process_os_pid, actor_process_is_special, actor_primary_username,
         causality_actor_process_image_name, causality_actor_process_image_path,
         causality_actor_process_command_line, causality_actor_process_os_pid,
         causality_actor_process_is_special,
         os_actor_process_image_name, os_actor_process_image_path,
         os_actor_process_command_line, os_actor_process_os_pid
| join conflict_strategy = left type = inner (
    dataset = loldrivers_hashes
    | fields sha256, sha1, md5, driver_name, category, verified, source_id, created
) as lol action_module_sha256 = lol.sha256
// Keep one row per host and driver hash. Prefer live user-mode context over
// System-only or replayed records without creating derived output fields.
| dedup agent_id, action_module_sha256, action_module_is_replay,
        actor_process_is_special, causality_actor_process_is_special by desc _time
| dedup agent_id, action_module_sha256, action_module_is_replay,
        actor_process_is_special by asc causality_actor_process_is_special
| dedup agent_id, action_module_sha256,
        action_module_is_replay by asc actor_process_is_special
| dedup agent_id, action_module_sha256 by asc action_module_is_replay
| fields _time, agent_hostname, agent_id, event_type, event_sub_type,
         action_module_sha256, action_module_path, action_module_is_replay,
         action_module_file_info, action_module_signature_status,
         action_module_signature_vendor, action_module_signature_product,
         driver_name, category, verified, source_id, created, sha1, md5,
         actor_process_image_name, actor_process_image_path, actor_process_command_line,
         actor_process_os_pid, actor_process_is_special, actor_primary_username,
         causality_actor_process_image_name, causality_actor_process_image_path,
         causality_actor_process_command_line, causality_actor_process_os_pid,
         causality_actor_process_is_special, os_actor_process_image_name,
         os_actor_process_image_path, os_actor_process_command_line, os_actor_process_os_pid
