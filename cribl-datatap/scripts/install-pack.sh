#!/bin/bash
# DataTap — 30-Second Installer
# Usage: ./install-pack.sh [container] [port] [user] [pass]
set -e
C=${1:-cribl-stream}; P=${2:-9001}; U=${3:-admin}; PW=${4:-admin}
DIR="$(cd "$(dirname "$0")/.." && pwd)/pack"

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║     DataTap — Installing...          ║"
echo "  ╚══════════════════════════════════════╝"

# Auth
T=$(curl -sf "http://localhost:$P/api/v1/auth/login" -H 'Content-Type: application/json' -d "{\"username\":\"$U\",\"password\":\"$PW\"}" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
[ -z "$T" ] && echo "  ERROR: Cannot authenticate" && exit 1

# Copy samples
for f in "$DIR"/default/data/samples/*.json; do
  docker cp "$f" "$C:/opt/cribl/data/samples/" 2>/dev/null
done

# Register samples
for S in datatap_top10 datatap_security datatap_o11y datatap_scenario_bruteforce datatap_scenario_normalday datatap_all datatap_pan_traffic datatap_syslog datatap_windows datatap_crowdstrike datatap_okta datatap_cisco_asa datatap_aws_cloudtrail datatap_fortinet datatap_zscaler datatap_azure_ad datatap_cloudflare; do
  curl -sf -X PATCH "http://localhost:$P/api/v1/system/samples/$S" -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d "{\"id\":\"$S\",\"isTemplate\":true}" > /dev/null 2>&1 || true
done

# Create pipeline with engine code
CODE=$(node -e "var f=require('fs').readFileSync('$DIR/default/cribl/pipelines/datatap_generate/conf.yml','utf8');var c=f.indexOf('code: |-\n')+9;process.stdout.write(JSON.stringify(f.substring(c).split('\n').map(function(l){return l.substring(8)}).join('\n')))")
curl -sf -X POST "http://localhost:$P/api/v1/pipelines?product=stream" -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d "{\"id\":\"datatap_generate\",\"conf\":{\"output\":\"default\",\"asyncFuncTimeout\":10000,\"functions\":[{\"id\":\"code\",\"filter\":\"true\",\"disabled\":false,\"conf\":{\"maxNumOfIterations\":5000,\"code\":$CODE}}]}}" > /dev/null 2>&1

# Create datagen source
curl -sf -X POST "http://localhost:$P/api/v1/system/inputs" -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d '{"id":"datatap","type":"datagen","disabled":false,"pipeline":"datatap_generate","samples":[{"sample":"datatap_top10","eventsPerSec":10}]}' > /dev/null 2>&1

# Commit
curl -sf -X POST "http://localhost:$P/api/v1/version/commit" -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d '{"message":"Install DataTap v2.0.1"}' > /dev/null 2>&1

echo ""
echo "  ✓ Done! DataTap is streaming."
echo ""
echo "  Open: http://localhost:$P"
echo "  Source: Data > Sources > Datagen > datatap"
echo ""
echo "  Switch sourcetypes by changing the datagen sample:"
echo "    datatap_top10              Top 10 enterprise"
echo "    datatap_security           Security (12 types)"
echo "    datatap_o11y               Observability (10 types)"
echo "    datatap_scenario_bruteforce  Brute force attack"
echo "    datatap_pan_traffic        PAN-OS only"
echo "    datatap_syslog             Syslog only"
echo "    datatap_windows            Windows Security only"
echo "    datatap_crowdstrike        CrowdStrike only"
echo "    datatap_okta               Okta only"
echo "    datatap_cisco_asa          Cisco ASA only"
echo "    datatap_aws_cloudtrail     AWS CloudTrail only"
echo "    datatap_fortinet           FortiGate only"
echo "    datatap_zscaler            Zscaler only"
echo ""
