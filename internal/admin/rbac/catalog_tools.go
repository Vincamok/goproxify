// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac

import "strings"

// toolPermissionGroups déclare, pour chaque outil MCP, la permission du catalogue qu'il exige. Un outil absent d'ici
// fait échouer TestEveryMCPToolDeclaresACataloguePermission ; la déclaration ne remplace pas ToolRequiredScope, qui
// reste le contrôle appliqué, et le même test vérifie que les deux restent d'accord.
var toolPermissionGroups = []struct {
	permission string
	tools      string
}{
	{"proxies:read", "list_proxies get_proxy get_proxy_labels list_orphan_proxies"},
	{"proxies:operate", "create_proxy update_proxy set_proxy_enabled purge_proxy_cache"},
	{"proxies:manage", "delete_proxy"},
	{"containers:read", "get_discovered_container"},
	{"containers:operate", "convert_discovered_container set_container_route_enabled"},

	{"infra:read", "list_nodes list_agents list_declared_nodes get_topology_live get_architecture list_hosts"},
	{"nodes:approve", "approve_agent revoke_agent accept_node reject_node"},
	{"architecture:write", "create_declared_node delete_declared_node"},
	{"infra:classify", "set_group_attributes"},
	{"enrol:create", "create_bootstrap_ticket create_host_join_ticket"},
	{"discovery:read", "list_discovery_sources"},

	{"alerts:read", "list_alerts list_alert_events list_alert_rules"},
	{"alerts:ack", "ack_alert_event"},
	{"alerts:rules", "create_alert_rule delete_alert_rule"},
	{"alert_channels:read", "list_alert_channels list_alert_channel_types"},
	{"alert_channels:manage", "create_alert_channel delete_alert_channel"},

	{"dashboard:read", "get_metrics get_proxy_metrics get_prism_anomalies get_prism_geo get_prism_tls_fingerprints get_prism_slo"},
	{"backups:list", "list_backups"},
	{"accounts:read", "list_users get_user_access list_teams"},

	{"snippets:read", "list_snippets list_detector_types"},
	{"snippets:write", "create_snippet delete_snippet"},

	{"domains:read", "list_domains"},
	{"domains:manage", "create_domain renew_domain rotate_cert"},
	{"certs:read", "list_certs get_cert_status list_cert_deploy_targets list_cert_deploy_types"},
	{"certs:manage", "obtain_cert import_cert"},
	{"certs:deploy", "trigger_cert_deploy"},
	{"pki:read", "list_internal_cas list_internal_certs get_ech_status list_dns_providers list_dns_provider_types"},
	{"pki:write", "create_internal_ca issue_internal_cert revoke_internal_cert"},

	{"logs:read", "list_logs"},
	{"logs_settings:read", "get_siem_status"},
	{"audit:read", "get_audit_log"},

	{"netsec:read", "get_security_overview list_security_bans get_waf_activity lookup_asn list_ban_whitelist list_security_threats list_security_cves get_app_inventory get_entry_rejections get_traffic_reference get_tls_reputation"},
	{"netsec:analyse", "trace_ip preview_security_ban preview_asn_ban"},
	{"netsec:respond", "create_security_ban delete_security_ban ban_ip unban_ip add_ban_whitelist remove_ban_whitelist ban_asn unban_asn"},
	{"bans:import", "import_security_bans"},
	{"engines:read", "list_security_engine_types"},
	{"engines:simulate", "simulate_ephor_config calibrate_ephor get_ephor_references suggest_ephor_thresholds"},
	{"surface:read", "get_proxy_surface get_proxy_surface_proposals get_proxy_surface_openapi get_proxy_surface_suggestions"},
	{"surface:learn", "reset_proxy_surface accept_proxy_surface_suggestions relax_proxy_surface"},
	{"surface:enforce", "enforce_proxy_surface"},
	{"domain_watch:read", "get_domain_watch"},
	{"plugins:read", "list_plugins"},
	{"ip_profiles:read", "list_ip_profiles"},
	{"ip_profiles:write", "create_ip_profile delete_ip_profile"},
	{"auth_providers:read", "list_auth_providers list_auth_provider_types"},
	{"auth_providers:write", "create_auth_provider delete_auth_provider"},

	{"automation:read", "list_flows get_flow list_flow_versions list_flow_runs get_flow_run get_automation_catalog list_flow_templates list_silences export_automation"},
	{"automation:edit", "create_flow update_flow set_flow_enabled delete_flow simulate_flow restore_flow_version detach_flow update_flow_params install_flow_template create_silence delete_silence import_automation"},
	{"automation:run", "run_flow cancel_flow_run replay_flow_run"},
	{"automation:approve", "decide_flow_run"},

	{"portal_catalog:read", "list_portal_destinations preview_portal_destinations list_portal_destination_groups"},
	{"portal_catalog:manage", "create_portal_destination update_portal_destination delete_portal_destination create_portal_destination_group update_portal_destination_group delete_portal_destination_group"},
	{"portal_users:read", "list_portal_users list_portal_groups"},
	{"portal_users:manage", "invite_portal_user create_portal_group update_portal_group delete_portal_group update_portal_user delete_portal_user resend_portal_invite"},
	{"portal_audit:read", "list_portal_audit"},
	{"portal_sessions:read", "list_portal_sessions"},
	{"portal_sessions:cut", "terminate_portal_session"},
	{"portal_requests:read", "list_portal_access_requests"},
	{"portal_requests:decide", "decide_portal_access_request"},
	{"portal_policies:read", "get_portal_policy"},
	{"portal_policies:manage", "set_portal_policy"},
	{"portal_recordings:list", "list_portal_recordings"},
	{"portal_recordings:delete", "delete_portal_recording"},
	{"portal_templates:read", "get_portal_config list_portal_templates get_portal_template"},
	{"portal_templates:manage", "update_portal_config push_portal upsert_portal_template delete_portal_template push_portal_templates"},
}

var toolPermission = func() map[string]string {
	m := map[string]string{}
	for _, g := range toolPermissionGroups {
		for _, tool := range strings.Fields(g.tools) {
			m[tool] = g.permission
		}
	}
	return m
}()

// ToolPermission renvoie la permission du catalogue qu'exige un outil MCP, "" s'il n'en déclare aucune.
func ToolPermission(tool string) string { return toolPermission[tool] }
