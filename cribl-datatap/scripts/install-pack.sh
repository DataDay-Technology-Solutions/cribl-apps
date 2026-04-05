#!/bin/bash
# DataTap Full Install — per-sourcetype datagen sources
C=${1:-$(docker ps --format "{{.Names}}" 2>/dev/null | grep -i cribl | head -1)}
[ -z "$C" ] && echo "No Cribl container found" && exit 1
P=$(docker port "$C" 9000 2>/dev/null | head -1 | cut -d: -f2)
[ -z "$P" ] && P=${2:-9001}
DIR="$(cd "$(dirname "$0")/.." && pwd)/pack"

echo "  Installing DataTap..."

T=$(curl -sf "http://localhost:$P/api/v1/auth/login" -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
[ -z "$T" ] && echo "  Cannot auth" && exit 1

# Copy samples
for f in "$DIR"/default/data/samples/*.json; do docker cp "$f" "$C:/opt/cribl/data/samples/" 2>/dev/null; done

# Engine
CODE=$(node -e "var f=require('fs').readFileSync(process.argv[1],'utf8'),c=f.indexOf('code: |-\n')+9;process.stdout.write(JSON.stringify(f.substring(c).split('\n').map(l=>l.substring(8)).join('\n')))" "$DIR/default/cribl/pipelines/datatap_generate/conf.yml" 2>/dev/null)
[ -n "$CODE" ] && curl -sf -X POST "http://localhost:$P/api/v1/pipelines?product=stream" -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d "{\"id\":\"datatap_generate\",\"conf\":{\"output\":\"default\",\"asyncFuncTimeout\":10000,\"functions\":[{\"id\":\"code\",\"filter\":\"true\",\"disabled\":false,\"conf\":{\"maxNumOfIterations\":5000,\"code\":$CODE}}]}}" > /dev/null 2>&1 || true

# Register samples
for S in datatap_top10 datatap_security datatap_o11y datatap_scenario_bruteforce datatap_scenario_normalday datatap_all datatap_pan datatap_syslog datatap_windows datatap_crowdstrike datatap_okta datatap_asa datatap_cloudtrail datatap_fortigate datatap_dns datatap_prometheus datatap_vpcflow datatap_zscaler; do
  curl -sf -X POST "http://localhost:$P/api/v1/system/samples" -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d "{\"id\":\"$S\",\"sampleName\":\"$S.json\",\"isTemplate\":true,\"created\":1775000000000,\"size\":100,\"numEvents\":1}" > /dev/null 2>&1 || true
done

# Create datagen sources — one per sourcetype
# Format: id|sample|disabled|description
SOURCES="datatap-top10|datatap_top10|true|Top 10 Enterprise (auto-cycling)
datatap-pan|datatap_pan|true|Palo Alto PAN-OS Traffic
datatap-syslog|datatap_syslog|true|Syslog RFC 5424
datatap-windows|datatap_windows|true|Windows Security Event Log
datatap-crowdstrike|datatap_crowdstrike|true|CrowdStrike Falcon
datatap-okta|datatap_okta|true|Okta System Log
datatap-asa|datatap_asa|true|Cisco ASA Firewall
datatap-cloudtrail|datatap_cloudtrail|true|AWS CloudTrail
datatap-fortigate|datatap_fortigate|true|Fortinet FortiGate
datatap-dns|datatap_dns|true|DNS Query Logs
datatap-prometheus|datatap_prometheus|true|Prometheus Metrics
datatap-zscaler|datatap_zscaler|true|Zscaler ZIA Web Proxy
datatap-security|datatap_security|true|Security Mix (12 sources)
datatap-o11y|datatap_o11y|true|Observability Mix (10 sources)
datatap-bruteforce|datatap_scenario_bruteforce|true|SCENARIO: Brute Force Attack"

echo "$SOURCES" | while IFS='|' read -r SID SAMPLE DISABLED DESC; do
  curl -sf -X POST "http://localhost:$P/api/v1/system/inputs" -H "Authorization: Bearer $T" -H "Content-Type: application/json" \
    -d "{\"id\":\"$SID\",\"type\":\"datagen\",\"disabled\":$DISABLED,\"pipeline\":\"datatap_generate\",\"samples\":[{\"sample\":\"$SAMPLE\",\"eventsPerSec\":10}],\"description\":\"DataTap: $DESC\"}" > /dev/null 2>&1 || true
done

curl -sf -X POST "http://localhost:$P/api/v1/version/commit" -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d '{"message":"Install DataTap v2.2"}' > /dev/null 2>&1

echo ""
echo "  ✓ DataTap installed!"
echo ""
echo "  Go to: Data > Sources > Datagen"
echo "  Enable the sources you want. Disable the ones you don't."
echo ""
