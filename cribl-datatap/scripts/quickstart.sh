#!/bin/bash
# DataTap QuickStart — ONE COMMAND, data in seconds
# Usage: ./quickstart.sh
#
# Auto-detects Cribl container and port. No arguments needed.

C=$(docker ps --format "{{.Names}}" 2>/dev/null | grep -i cribl | head -1)
[ -z "$C" ] && echo "No Cribl container found" && exit 1
P=$(docker port "$C" 9000 2>/dev/null | head -1 | cut -d: -f2)
[ -z "$P" ] && P=9001
T=$(curl -sf "http://localhost:$P/api/v1/auth/login" -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
[ -z "$T" ] && echo "Can't auth to Cribl" && exit 1

# Inject engine + create source in parallel
CODE=$(cat "$(dirname "$0")/../pack/default/cribl/pipelines/datatap_generate/conf.yml" | sed -n '/code: |-/,$ p' | tail -n +2 | sed 's/^        //')
ESCAPED=$(node -e "process.stdout.write(JSON.stringify(require('fs').readFileSync(0,'utf8')))" <<< "$CODE")

curl -sf -X POST "http://localhost:$P/api/v1/pipelines?product=stream" -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d "{\"id\":\"datatap_generate\",\"conf\":{\"output\":\"default\",\"asyncFuncTimeout\":10000,\"functions\":[{\"id\":\"code\",\"filter\":\"true\",\"disabled\":false,\"conf\":{\"maxNumOfIterations\":5000,\"code\":$ESCAPED}}]}}" > /dev/null 2>&1 &

curl -sf -X POST "http://localhost:$P/api/v1/system/inputs" -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d '{"id":"datatap","type":"datagen","disabled":false,"pipeline":"datatap_generate","samples":[{"sample":"syslog","eventsPerSec":10}]}' > /dev/null 2>&1 &

wait
curl -sf -X POST "http://localhost:$P/api/v1/version/commit" -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d '{"message":"DataTap"}' > /dev/null 2>&1

echo "✓ DataTap streaming at http://localhost:$P"
echo "  Source: Data > Sources > Datagen > datatap"
