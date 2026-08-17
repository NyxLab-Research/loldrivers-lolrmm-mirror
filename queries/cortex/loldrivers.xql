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
| alter normalized_module_path = lowercase(coalesce(action_module_path, "unknown")),
        driver_company = coalesce(json_extract_scalar(action_module_file_info, "$.company"), action_module_signature_vendor),
        driver_description = json_extract_scalar(action_module_file_info, "$.description"),
        driver_product_name = coalesce(json_extract_scalar(action_module_file_info, "$.product_name"), action_module_signature_product, driver_name),
        driver_product_version = json_extract_scalar(action_module_file_info, "$.product_version"),
        driver_file_version = json_extract_scalar(action_module_file_info, "$.file_version"),
        driver_original_name = coalesce(json_extract_scalar(action_module_file_info, "$.original_name"), driver_name)
| alter associated_process_name = if(actor_process_is_special = 0, actor_process_image_name,
                                     causality_actor_process_is_special = 0, causality_actor_process_image_name, "Not available"),
        associated_process_path = if(actor_process_is_special = 0, actor_process_image_path,
                                     causality_actor_process_is_special = 0, causality_actor_process_image_path, "Not available"),
        associated_process_command_line = if(actor_process_is_special = 0, actor_process_command_line,
                                             causality_actor_process_is_special = 0, causality_actor_process_command_line, "Not available"),
        observation_type = if(action_module_is_replay = true, "Replay - original user-mode context unavailable",
                              actor_process_is_special = 0 or causality_actor_process_is_special = 0, "Live - user-mode context available",
                              "Live - kernel context only"),
        context_priority = if(action_module_is_replay = false and actor_process_is_special = 0, 3,
                              action_module_is_replay = false and causality_actor_process_is_special = 0, 2,
                              action_module_is_replay = false, 1, 0)
// Prefer live user-mode context over its paired System event. Keep replayed
// events when no live context exists so boot-time vulnerable drivers are visible.
| dedup agent_id, action_module_sha256, normalized_module_path, context_priority by desc _time
| dedup agent_id, action_module_sha256, normalized_module_path by desc context_priority
| fields _time, agent_hostname, agent_id, event_type, event_sub_type, observation_type,
         action_module_is_replay, action_module_path, normalized_module_path,
         action_module_sha256, driver_original_name, driver_name, driver_description,
         driver_product_name, driver_product_version, driver_file_version, driver_company,
         category, verified, source_id, created, action_module_signature_status,
         action_module_signature_vendor, action_module_signature_product,
         associated_process_name, associated_process_path, associated_process_command_line,
         actor_process_image_name, actor_process_image_path, actor_process_command_line,
         actor_process_os_pid, actor_process_is_special, actor_primary_username,
         causality_actor_process_image_name, causality_actor_process_image_path,
         causality_actor_process_command_line, causality_actor_process_os_pid,
         causality_actor_process_is_special, os_actor_process_image_name,
         os_actor_process_image_path, os_actor_process_command_line, os_actor_process_os_pid
