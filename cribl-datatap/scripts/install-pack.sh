#!/bin/bash
# DataTap Full Install — 115 datagen sources for every sourcetype
C=${1:-$(docker ps --format "{{.Names}}" 2>/dev/null | grep -i cribl | head -1)}
[ -z "$C" ] && echo "No Cribl container found" && exit 1
P=$(docker port "$C" 9000 2>/dev/null | head -1 | cut -d: -f2)
[ -z "$P" ] && P=${2:-9001}
DIR="$(cd "$(dirname "$0")/.." && pwd)/pack"
echo "  Installing DataTap (115 sources)..."
T=$(curl -sf "http://localhost:$P/api/v1/auth/login" -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
[ -z "$T" ] && echo "  Cannot auth" && exit 1

# Copy ALL sample files
for f in "$DIR"/default/data/samples/*.json; do docker cp "$f" "$C:/opt/cribl/data/samples/" 2>/dev/null; done

# Write samples.yml to disk (persists through restart)
docker cp "$DIR/default/cribl/samples.yml" "$C:/opt/cribl/local/cribl/samples.yml" 2>/dev/null
docker exec "$C" mkdir -p /opt/cribl/local/cribl 2>/dev/null
docker cp "$DIR/default/cribl/samples.yml" "$C:/opt/cribl/local/cribl/samples.yml"

# Install engine pipeline
CODE=$(node -e "var f=require('fs').readFileSync(process.argv[1],'utf8'),c=f.indexOf('code: |-\n')+9;process.stdout.write(JSON.stringify(f.substring(c).split('\n').map(l=>l.substring(8)).join('\n')))" "$DIR/default/cribl/pipelines/datatap_generate/conf.yml" 2>/dev/null)
[ -n "$CODE" ] && curl -sf -X POST "http://localhost:$P/api/v1/pipelines?product=stream" -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d "{\"id\":\"datatap_generate\",\"conf\":{\"output\":\"default\",\"asyncFuncTimeout\":10000,\"functions\":[{\"id\":\"code\",\"filter\":\"true\",\"disabled\":false,\"conf\":{\"maxNumOfIterations\":5000,\"code\":$CODE}}]}}" > /dev/null 2>&1 || true

# Create ALL datagen sources
SOURCES="
datatap-pan-traffic|datatap_pan_traffic|true|pan:traffic
datatap-syslog|datatap_syslog|true|syslog
datatap-WinEventLog-Security|datatap_WinEventLog_Security|true|WinEventLog:Security
datatap-crowdstrike-falcon-event|datatap_crowdstrike_falcon_event|true|crowdstrike:falcon:event
datatap-okta-system|datatap_okta_system|true|okta:system
datatap-cisco-asa|datatap_cisco_asa|true|cisco:asa
datatap-aws-cloudtrail|datatap_aws_cloudtrail|true|aws:cloudtrail
datatap-fortigate-traffic|datatap_fortigate_traffic|true|fortigate:traffic
datatap-aws-cloudwatchlogs-vpcflow|datatap_aws_cloudwatchlogs_vpcflow|true|aws:cloudwatchlogs:vpcflow
datatap-zscalernss-web|datatap_zscalernss-web|true|zscalernss-web
datatap-checkpoint-firewall|datatap_checkpoint_firewall|true|checkpoint:firewall
datatap-juniper-srx|datatap_juniper_srx|true|juniper:srx
datatap-sophos-utm|datatap_sophos_utm|true|sophos:utm
datatap-sonicwall-fw|datatap_sonicwall_fw|true|sonicwall:fw
datatap-pfsense-filterlog|datatap_pfsense_filterlog|true|pfsense:filterlog
datatap-sentinelone-threat|datatap_sentinelone_threat|true|sentinelone:threat
datatap-carbon-black-defense|datatap_carbon_black_defense|true|carbon_black:defense
datatap-ms-defender-endpoint|datatap_ms_defender_endpoint|true|ms:defender:endpoint
datatap-cortex-xdr|datatap_cortex_xdr|true|cortex:xdr
datatap-wazuh-alert|datatap_wazuh_alert|true|wazuh:alert
datatap-elastic-security|datatap_elastic_security|true|elastic:security
datatap-duo-authentication|datatap_duo_authentication|true|duo:authentication
datatap-azure-aad-signin|datatap_azure_aad_signin|true|azure:aad:signin
datatap-auth0-log|datatap_auth0_log|true|auth0:log
datatap-cyberark-vault|datatap_cyberark_vault|true|cyberark:vault
datatap-beyondtrust-pam|datatap_beyondtrust_pam|true|beyondtrust:pam
datatap-aws-guardduty|datatap_aws_guardduty|true|aws:guardduty
datatap-aws-securityhub|datatap_aws_securityhub|true|aws:securityhub
datatap-aws-waf|datatap_aws_waf|true|aws:waf
datatap-aws-lambda|datatap_aws_lambda|true|aws:lambda
datatap-aws-config|datatap_aws_config|true|aws:config
datatap-aws-inspector|datatap_aws_inspector|true|aws:inspector
datatap-aws-route53|datatap_aws_route53|true|aws:route53
datatap-gcp-audit|datatap_gcp_audit|true|gcp:audit
datatap-gcp-firewall|datatap_gcp_firewall|true|gcp:firewall
datatap-azure-activity|datatap_azure_activity|true|azure:activity
datatap-azure-nsg-flow|datatap_azure_nsg_flow|true|azure:nsg:flow
datatap-azure-firewall|datatap_azure_firewall|true|azure:firewall
datatap-azure-keyvault|datatap_azure_keyvault|true|azure:keyvault
datatap-o365-management-activity|datatap_o365_management_activity|true|o365:management:activity
datatap-proofpoint-tap|datatap_proofpoint_tap|true|proofpoint:tap
datatap-squid-access|datatap_squid_access|true|squid:access
datatap-dns-query|datatap_dns_query|true|dns:query
datatap-mimecast-email|datatap_mimecast_email|true|mimecast:email
datatap-tenable-vuln|datatap_tenable_vuln|true|tenable:vuln
datatap-snyk-vuln|datatap_snyk_vuln|true|snyk:vuln
datatap-prometheus-metrics|datatap_prometheus_metrics|true|prometheus:metrics
datatap-statsd-metric|datatap_statsd_metric|true|statsd:metric
datatap-graphite-metric|datatap_graphite_metric|true|graphite:metric
datatap-influxdb-metric|datatap_influxdb_metric|true|influxdb:metric
datatap-cloudwatch-metric|datatap_cloudwatch_metric|true|cloudwatch:metric
datatap-otel-metrics|datatap_otel_metrics|true|otel:metrics
datatap-otel-traces|datatap_otel_traces|true|otel:traces
datatap-jaeger-span|datatap_jaeger_span|true|jaeger:span
datatap-zipkin-span|datatap_zipkin_span|true|zipkin:span
datatap-aws-xray-segment|datatap_aws_xray_segment|true|aws:xray:segment
datatap-datadog-apm-span|datatap_datadog_apm_span|true|datadog:apm:span
datatap-app-java-log4j|datatap_app_java_log4j|true|app:java:log4j
datatap-app-python-log|datatap_app_python_log|true|app:python:log
datatap-app-node-pino|datatap_app_node_pino|true|app:node:pino
datatap-app-go-slog|datatap_app_go_slog|true|app:go:slog
datatap-app-dotnet-log|datatap_app_dotnet_log|true|app:dotnet:log
datatap-k8s-container-log|datatap_k8s_container_log|true|k8s:container:log
datatap-docker-container-stats|datatap_docker_container_stats|true|docker:container:stats
datatap-otel-logs|datatap_otel_logs|true|otel:logs
datatap-cloudwatch-logs|datatap_cloudwatch_logs|true|cloudwatch:logs
datatap-gcp-logging|datatap_gcp_logging|true|gcp:logging
datatap-sentry-event|datatap_sentry_event|true|sentry:event
datatap-healthcheck-result|datatap_healthcheck_result|true|healthcheck:result
datatap-ssl-certificate|datatap_ssl_certificate|true|ssl:certificate
datatap-datadog-event|datatap_datadog_event|true|datadog:event
datatap-nagios-event|datatap_nagios_event|true|nagios:event
datatap-icinga-event|datatap_icinga_event|true|icinga:event
datatap-splunk-audit|datatap_splunk_audit|true|splunk:audit
datatap-splunk-internal|datatap_splunk_internal|true|splunk:internal
datatap-linux-auditd|datatap_linux_auditd|true|linux:auditd
datatap-apache-access|datatap_apache_access|true|apache:access
datatap-nginx-access|datatap_nginx_access|true|nginx:access
datatap-netflow-v9|datatap_netflow_v9|true|netflow:v9
datatap-zeek-conn|datatap_zeek_conn|true|zeek:conn
datatap-zeek-dns|datatap_zeek_dns|true|zeek:dns
datatap-zeek-http|datatap_zeek_http|true|zeek:http
datatap-suricata-eve|datatap_suricata_eve|true|suricata:eve
datatap-snort-alert|datatap_snort_alert|true|snort:alert
datatap-darktrace-alert|datatap_darktrace_alert|true|darktrace:alert
datatap-vectra-detection|datatap_vectra_detection|true|vectra:detection
datatap-mysql-general|datatap_mysql_general|true|mysql:general
datatap-postgresql-query|datatap_postgresql_query|true|postgresql:query
datatap-mongodb-query|datatap_mongodb_query|true|mongodb:query
datatap-redis-command|datatap_redis_command|true|redis:command
datatap-mssql-audit|datatap_mssql_audit|true|mssql:audit
datatap-kubernetes-audit|datatap_kubernetes_audit|true|kubernetes:audit
datatap-kubernetes-events|datatap_kubernetes_events|true|kubernetes:events
datatap-jenkins-build|datatap_jenkins_build|true|jenkins:build
datatap-gitlab-pipeline|datatap_gitlab_pipeline|true|gitlab:pipeline
datatap-argocd-event|datatap_argocd_event|true|argocd:event
datatap-terraform-audit|datatap_terraform_audit|true|terraform:audit
datatap-ansible-log|datatap_ansible_log|true|ansible:log
datatap-vmware-vsphere|datatap_vmware_vsphere|true|vmware:vsphere
datatap-docker-events|datatap_docker_events|true|docker:events
datatap-cef-generic|datatap_cef_generic|true|cef:generic
datatap-leef-generic|datatap_leef_generic|true|leef:generic
datatap-hec-event|datatap_hec_event|true|hec:event
datatap-ndjson-event|datatap_ndjson_event|true|ndjson:event
datatap-salesforce-event|datatap_salesforce_event|true|salesforce:event
datatap-servicenow-audit|datatap_servicenow_audit|true|servicenow:audit
datatap-jira-audit|datatap_jira_audit|true|jira:audit
datatap-slack-audit|datatap_slack_audit|true|slack:audit
datatap-github-audit|datatap_github_audit|true|github:audit
datatap-top10|datatap_top10|true|Top 10 Enterprise (auto-cycling)
datatap-security|datatap_security|true|Security Mix (12 sources)
datatap-o11y|datatap_o11y|true|Observability Mix (10 sources)
datatap-scenario-bruteforce|datatap_scenario_bruteforce|true|SCENARIO: Brute Force Attack
datatap-scenario-normalday|datatap_scenario_normalday|true|SCENARIO: Normal Business Day
datatap-all|datatap_all|true|Core 5 sourcetypes
"
echo "$SOURCES" | while IFS='|' read -r SID SAMPLE DISABLED DESC; do
  [ -z "$SID" ] && continue
  curl -sf -X POST "http://localhost:$P/api/v1/system/inputs" -H "Authorization: Bearer $T" -H "Content-Type: application/json" \
    -d "{\"id\":\"$SID\",\"type\":\"datagen\",\"disabled\":$DISABLED,\"pipeline\":\"datatap_generate\",\"samples\":[{\"sample\":\"$SAMPLE\",\"eventsPerSec\":10}],\"description\":\"DataTap: $DESC\"}" > /dev/null 2>&1 || true
done

# Commit + restart for samples.yml to take effect
curl -sf -X POST "http://localhost:$P/api/v1/version/commit" -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d '{"message":"Install DataTap v2.3"}' > /dev/null 2>&1
docker restart "$C" > /dev/null 2>&1
echo "  Waiting for restart..."
sleep 15

# Recreate pipeline after restart
T2=$(curl -sf "http://localhost:$P/api/v1/auth/login" -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
[ -n "$CODE" ] && [ -n "$T2" ] && curl -sf -X POST "http://localhost:$P/api/v1/pipelines?product=stream" -H "Authorization: Bearer $T2" -H "Content-Type: application/json" -d "{\"id\":\"datatap_generate\",\"conf\":{\"output\":\"default\",\"asyncFuncTimeout\":10000,\"functions\":[{\"id\":\"code\",\"filter\":\"true\",\"disabled\":false,\"conf\":{\"maxNumOfIterations\":5000,\"code\":$CODE}}]}}" > /dev/null 2>&1 || true
curl -sf -X POST "http://localhost:$P/api/v1/version/commit" -H "Authorization: Bearer $T2" -H "Content-Type: application/json" -d '{"message":"pipeline"}' > /dev/null 2>&1

echo ""
echo "  ✓ DataTap installed with 115 sources!"
echo "  Go to: Data > Sources > Datagen"
echo "  Enable any source you want."
echo ""
echo "  (Cribl is restarting — wait ~15 seconds)"
echo ""
