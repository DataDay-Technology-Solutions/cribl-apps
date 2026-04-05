#!/bin/bash
# DataTap — Instant Installer
# Usage: ./install-pack.sh [container] [port] [user] [pass]
#
# If no container specified, auto-detects running Cribl container.
# If no port specified, auto-detects from Docker port mapping.

set -e

DIR="$(cd "$(dirname "$0")/.." && pwd)/pack"

# Auto-detect container if not specified
if [ -z "$1" ]; then
  C=$(docker ps --filter "ancestor=cribl/cribl" --format "{{.Names}}" 2>/dev/null | head -1)
  [ -z "$C" ] && C=$(docker ps --format "{{.Names}}" 2>/dev/null | grep -i cribl | head -1)
  [ -z "$C" ] && echo "ERROR: No Cribl container found. Specify: ./install-pack.sh <container_name>" && exit 1
  echo "  Auto-detected container: $C"
else
  C=$1
fi

# Auto-detect port if not specified
if [ -z "$2" ]; then
  P=$(docker port "$C" 9000 2>/dev/null | head -1 | cut -d: -f2)
  [ -z "$P" ] && P=9001
  echo "  Auto-detected port: $P"
else
  P=$2
fi

U=${3:-admin}; PW=${4:-admin}

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║     DataTap — Installing...          ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

# Auth
T=$(curl -sf "http://localhost:$P/api/v1/auth/login" -H 'Content-Type: application/json' -d "{\"username\":\"$U\",\"password\":\"$PW\"}" | grep -o '"token":"[^"]*"' | cut -d'"' -f4 2>/dev/null)
[ -z "$T" ] && echo "  ERROR: Cannot authenticate to Cribl at localhost:$P" && exit 1

# Copy samples
for f in "$DIR"/default/data/samples/*.json; do
  docker cp "$f" "$C:/opt/cribl/data/samples/" 2>/dev/null
done

# Register ALL samples with isTemplate
for S in datatap_top10 datatap_security datatap_o11y datatap_scenario_bruteforce datatap_scenario_normalday datatap_all datatap_pan_traffic datatap_syslog datatap_windows datatap_crowdstrike datatap_okta datatap_cisco_asa datatap_aws_cloudtrail datatap_fortinet datatap_zscaler datatap_azure_ad datatap_cloudflare datatap_vpcflow datatap_k8s_audit; do
  curl -sf -X PATCH "http://localhost:$P/api/v1/system/samples/$S" -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d "{\"id\":\"$S\",\"isTemplate\":true}" > /dev/null 2>&1 || true
done

# Create pipeline
CODE=$(node -e "var f=require('fs').readFileSync('$DIR/default/cribl/pipelines/datatap_generate/conf.yml','utf8');var c=f.indexOf('code: |-\n')+9;process.stdout.write(JSON.stringify(f.substring(c).split('\n').map(function(l){return l.substring(8)}).join('\n')))" 2>/dev/null)
if [ -n "$CODE" ]; then
  curl -sf -X POST "http://localhost:$P/api/v1/pipelines?product=stream" -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d "{\"id\":\"datatap_generate\",\"conf\":{\"output\":\"default\",\"asyncFuncTimeout\":10000,\"functions\":[{\"id\":\"code\",\"filter\":\"true\",\"disabled\":false,\"conf\":{\"maxNumOfIterations\":5000,\"code\":$CODE}}]}}" > /dev/null 2>&1
fi

# Create datagen source (default: top 10 at 10 EPS)
curl -sf -X POST "http://localhost:$P/api/v1/system/inputs" -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d '{"id":"datatap","type":"datagen","disabled":false,"pipeline":"datatap_generate","samples":[{"sample":"datatap_top10","eventsPerSec":10}]}' > /dev/null 2>&1

# Commit
curl -sf -X POST "http://localhost:$P/api/v1/version/commit" -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d '{"message":"Install DataTap"}' > /dev/null 2>&1

echo "  ✓ Installed! DataTap is streaming at 10 EPS."
echo ""
echo "  Cribl UI: http://localhost:$P"
echo ""
echo "  To switch data sources, edit the datagen source and"
echo "  change the sample to any of these:"
echo ""
echo "  MIXES:"
echo "    datatap_top10                Top 10 enterprise sourcetypes"
echo "    datatap_security             12 security sources"
echo "    datatap_o11y                 10 observability sources"
echo ""
echo "  SCENARIOS:"
echo "    datatap_scenario_bruteforce  Correlated brute-force attack"
echo "    datatap_scenario_normalday   Normal business day"
echo ""
echo "  INDIVIDUAL:"
echo "    datatap_pan_traffic          Palo Alto PAN-OS"
echo "    datatap_syslog               Syslog RFC 5424"
echo "    datatap_windows              Windows Security"
echo "    datatap_crowdstrike          CrowdStrike Falcon"
echo "    datatap_okta                 Okta System Log"
echo "    datatap_cisco_asa            Cisco ASA"
echo "    datatap_aws_cloudtrail       AWS CloudTrail"
echo "    datatap_fortinet             FortiGate"
echo "    datatap_zscaler              Zscaler ZIA"
echo "    datatap_vpcflow              AWS VPC Flow"
echo "    datatap_k8s_audit            Kubernetes Audit"
echo ""
