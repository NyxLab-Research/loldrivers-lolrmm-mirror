// Cortex XDR: weekly report query for known RMM domain activity.
// Maintain the Cortex lookup dataset `lolrmm_domains` with the Ubuntu/API
// synchronizer documented in docs/CORTEX_SERVER_SYNC.md. The contains branch
// handles subdomains; investigate/allowlist sanctioned domains in the lookup
// or query.
config timeframe = 7d
| dataset = xdr_data
| filter action_external_hostname != null
| alter remote_host = lowercase(action_external_hostname)
// Optional exact-host allowlist, for example:
// | filter remote_host not in ("approved-rmm.example")
| fields _time,
         agent_hostname,
         agent_id,
         remote_host,
         actor_process_image_name,
         actor_process_image_path,
         actor_process_command_line,
         actor_primary_username,
         event_type,
         event_sub_type
| comp
    min(_time) as first_seen,
    max(_time) as last_seen,
    count() as event_count,
    values(actor_primary_username) as usernames,
    values(event_type) as event_types,
    values(event_sub_type) as event_sub_types,
    values(actor_process_image_path) as process_paths,
    values(actor_process_command_line) as command_lines
  by agent_hostname,
     agent_id,
     remote_host,
     actor_process_image_name
| join conflict_strategy = left type = inner (
    dataset = lolrmm_domains
    | filter domain != null
    | comp
        values(rmm_tool) as rmm_tools,
        values(pattern) as patterns
      by domain
) as rmm
  remote_host = rmm.domain
  or remote_host contains concat(".", rmm.domain)
| fields first_seen,
         last_seen,
         event_count,
         agent_hostname,
         agent_id,
         remote_host,
         domain,
         rmm_tools,
         patterns,
         actor_process_image_name,
         process_paths,
         command_lines,
         usernames,
         event_types,
         event_sub_types
