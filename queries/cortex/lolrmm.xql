// Cortex XDR RMM report; requires the `lolrmm_domains` lookup.
// Report window: 7d (change to 30d as needed); validation window: at most 1d.
// event_count counts events; values() arrays are independent sets.
// Official references:
// https://docs-cortex.paloaltonetworks.com/r/Cortex-XQL-Schema-Reference-Guide/Actor-Actor
// https://docs-cortex.paloaltonetworks.com/r/Cortex-XQL-Schema-Reference-Guide/XDR_DATA-Fields
// https://docs-cortex.paloaltonetworks.com/r/Cortex/Cortex-XQL-Command-Reference/comp
config timeframe = 7d
| dataset = xdr_data
| filter action_external_hostname != null
| alter remote_host = lowercase(action_external_hostname)
// Optional exact-host allowlist:
// | filter remote_host not in ("approved-rmm.example")
| fields _time,
         agent_hostname,
         agent_id,
         remote_host,
         actor_process_image_name,
         actor_process_image_path,
         actor_process_image_sha256,
         actor_process_command_line,
         actor_process_signature_status,
         actor_process_signature_vendor,
         actor_primary_username,
         actor_effective_username,
         action_local_ip,
         action_remote_ip,
         action_remote_port,
         actor_process_instance_id,
         actor_process_os_pid,
         event_type,
         event_sub_type
| comp
    min(_time) as first_seen,
    max(_time) as last_seen,
    count() as event_count,
    values(actor_primary_username) as usernames,
    values(actor_effective_username) as effective_usernames,
    values(actor_process_signature_status) as signature_statuses,
    values(actor_process_signature_vendor) as signature_vendors,
    values(action_local_ip) as local_ips,
    values(action_remote_ip) as remote_ips,
    values(action_remote_port) as remote_ports,
    values(actor_process_instance_id) as process_instance_ids,
    values(actor_process_os_pid) as process_ids,
    values(event_type) as event_types,
    values(event_sub_type) as event_sub_types,
    values(actor_process_command_line) as command_lines
  by agent_hostname,
     agent_id,
     remote_host,
     actor_process_image_name,
     actor_process_image_path,
     actor_process_image_sha256
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
| fields agent_hostname,
         rmm_tools,
         first_seen,
         last_seen,
         event_count,
         actor_process_image_name,
         actor_process_image_path,
         actor_process_image_sha256,
         signature_statuses,
         signature_vendors,
         usernames,
         effective_usernames,
         command_lines,
         remote_host,
         remote_ips,
         remote_ports,
         local_ips,
         domain,
         patterns,
         agent_id,
         process_instance_ids,
         process_ids,
         event_types,
         event_sub_types
