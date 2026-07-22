// Cortex XDR: LOLDrivers BYOVD hunting.
// Import data/loldrivers_hashes.csv as a Cortex lookup dataset named
// `loldrivers_hashes` before running this query. XQL cannot read GitHub URLs
// with KQL-style externaldata(). See docs/DEPLOYMENT.md.
// action_module_sha256 represents the closer driver/module-load signal. The
// action_file_sha256 branch also finds known drivers written or accessed on an
// endpoint and is intentionally broader than MDE ActionType="DriverLoad".
config timeframe = 30d
| dataset = xdr_data
| filter action_module_sha256 != null or action_file_sha256 != null
| join type = inner (
    dataset = loldrivers_hashes
    | fields sha256, sha1, md5, driver_name, category, verified, source_id, created
) as lol action_module_sha256 = lol.sha256 or action_file_sha256 = lol.sha256
| fields _time, agent_hostname, agent_id, agent_os_type, event_type, event_sub_type,
         action_module_sha256, action_file_sha256, action_file_name, action_file_path,
         event_address_mapped_image_path,
         action_process_image_name, action_process_image_path, lol.driver_name,
         lol.category, lol.verified, lol.source_id, lol.created
