// Cortex XDR: known RMM domain hunting.
// Maintain the Cortex lookup dataset `lolrmm_domains` with the Ubuntu/API
// synchronizer documented in docs/CORTEX_SERVER_SYNC.md. The contains branch
// handles subdomains; investigate/allowlist sanctioned domains in the lookup
// or query.
config timeframe = 1h
| dataset = xdr_data
| filter action_external_hostname != null
| alter remote_host = lowercase(action_external_hostname)
// Optional exact-host allowlist, for example:
// | filter remote_host not in ("approved-rmm.example")
| join type = inner (
    dataset = lolrmm_domains
    | filter domain != null
    | fields domain, rmm_tool, pattern
) as rmm remote_host = rmm.domain or remote_host contains concat(".", rmm.domain)
| fields _time, agent_hostname, agent_id, event_type, event_sub_type,
         action_external_hostname, action_remote_ip, action_remote_port,
         action_process_image_name, action_process_image_path,
         domain, rmm_tool, pattern
