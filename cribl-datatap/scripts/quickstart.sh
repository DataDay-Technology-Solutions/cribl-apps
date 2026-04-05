#!/bin/bash
# DataTap QuickStart — plug and play
ST=${1:-all}; EPS=${2:-10}; HOST=${3:-localhost}; PORT=${4:-9001}

[ "$ST" = "--list" ] && echo "Sources: pan:traffic syslog WinEventLog:Security crowdstrike:falcon:event okta:system cisco:asa aws:cloudtrail fortigate:traffic dns:query prometheus:metrics | Presets: all brute-force" && exit 0
[ "$ST" = "--stop" ] && { T=$(curl -sf "http://$HOST:$PORT/api/v1/auth/login" -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4); curl -sf -X PATCH "http://$HOST:$PORT/api/v1/system/inputs/datatap" -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d '{"id":"datatap","disabled":true}' > /dev/null; curl -sf -X POST "http://$HOST:$PORT/api/v1/version/commit" -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d '{"message":"stop"}' > /dev/null; echo "Stopped."; exit 0; }

C=$(docker ps --format "{{.Names}}" 2>/dev/null | grep -i cribl | head -1)
[ -n "$C" ] && [ "$HOST" = "localhost" ] && PORT=$(docker port "$C" 9000 2>/dev/null | head -1 | cut -d: -f2)
[ -z "$PORT" ] && PORT=9001
T=$(curl -sf "http://$HOST:$PORT/api/v1/auth/login" -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
[ -z "$T" ] && echo "Cannot connect to Cribl" && exit 1

# Install engine
EDIR="$(cd "$(dirname "$0")/.." && pwd)/pack/default/cribl/pipelines/datatap_generate/conf.yml"
if [ -f "$EDIR" ]; then
  CODE=$(node -e "var f=require('fs').readFileSync(process.argv[1],'utf8'),c=f.indexOf('code: |-\n')+9;process.stdout.write(JSON.stringify(f.substring(c).split('\n').map(l=>l.substring(8)).join('\n')))" "$EDIR" 2>/dev/null)
  [ -n "$CODE" ] && curl -sf -X POST "http://$HOST:$PORT/api/v1/pipelines?product=stream" -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d "{\"id\":\"datatap_generate\",\"conf\":{\"output\":\"default\",\"asyncFuncTimeout\":10000,\"functions\":[{\"id\":\"code\",\"filter\":\"true\",\"disabled\":false,\"conf\":{\"maxNumOfIterations\":5000,\"code\":$CODE}}]}}" > /dev/null 2>&1 || true
fi

# Create sample for specific sourcetype
SAMPLE="syslog"
if [ "$ST" != "all" ] && [ -n "$C" ]; then
  node -e "require('fs').writeFileSync('/tmp/dt.json',JSON.stringify([{_raw:JSON.stringify({_datatap:true,sourcetype:process.argv[1]}),_time:1}]))" "$ST"
  docker cp /tmp/dt.json "$C:/opt/cribl/data/samples/datatap_pick.json" > /dev/null 2>&1
  curl -sf -X POST "http://$HOST:$PORT/api/v1/system/samples" -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d '{"id":"datatap_pick","sampleName":"datatap_pick.json","isTemplate":true,"created":1775000000000,"size":100,"numEvents":1}' > /dev/null 2>&1 || true
  SAMPLE="datatap_pick"
fi

# Create source
curl -sf -X DELETE "http://$HOST:$PORT/api/v1/system/inputs/datatap" -H "Authorization: Bearer $T" > /dev/null 2>&1 || true
curl -sf -X POST "http://$HOST:$PORT/api/v1/system/inputs" -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d "{\"id\":\"datatap\",\"type\":\"datagen\",\"disabled\":false,\"pipeline\":\"datatap_generate\",\"samples\":[{\"sample\":\"$SAMPLE\",\"eventsPerSec\":$EPS}]}" > /dev/null 2>&1 || true
curl -sf -X POST "http://$HOST:$PORT/api/v1/version/commit" -H "Authorization: Bearer $T" -H "Content-Type: application/json" -d '{"message":"DataTap"}' > /dev/null 2>&1

echo "✓ DataTap: $ST @ ${EPS} EPS → http://$HOST:$PORT"
