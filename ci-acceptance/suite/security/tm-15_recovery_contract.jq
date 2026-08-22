def cleanup_resources:
  ["cgroup", "lease_unit", "proxy_object_state", "runtime_socket", "workspace"];

.state == "clean" and
.emptied == true and
.quarantined == false and
.before_reuse == true and
.reuse_allowed == true and
(.quarantined_resources | type == "array" and length == 0) and
(.emptied_resources | type == "array") and
(if $target == "cleanup_adapter_recovery" then
   (.emptied_resources | sort) == cleanup_resources
 elif $target == "dns_adapter_recovery" then
   (.emptied_resources | index("network_namespace")) != null
 else
   false
 end) and
($old_lease | length) > 0 and
($new_lease | length) > 0 and
$new_lease != $old_lease and
($old_workspace | length) > 0 and
($new_workspace | length) > 0 and
$new_workspace != $old_workspace
