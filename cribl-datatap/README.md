# DataTap — Streaming Sample Data for Cribl Stream

Generate production-realistic streaming data for 110+ sourcetypes. One command to install, data flows in seconds.

## Install

You need a running Cribl Stream instance (Docker, VM, or bare metal).

### Docker

```bash
git clone https://github.com/DataDay-Technology-Solutions/cribl-apps.git
cd cribl-apps/cribl-datatap
bash scripts/install.sh
```

The script auto-detects your Cribl container. If you have multiple containers or a custom name:

```bash
bash scripts/install.sh my-cribl-container 9001
```

That's it. Open your Cribl UI. `datatap-top10` is already streaming.

### Non-Docker (VM / bare metal)

Copy the files manually to your Cribl install directory:

```bash
# Copy samples
cp pack/default/data/samples/datatap_*.json /opt/cribl/data/samples/

# Copy config
cp pack/default/cribl/samples.yml /opt/cribl/local/cribl/samples.yml
cp pack/default/cribl/inputs_standalone.yml /opt/cribl/local/cribl/inputs.yml

# Copy pipeline
mkdir -p /opt/cribl/local/cribl/pipelines/datatap_generate
cp pack/default/cribl/pipelines/datatap_generate/conf.yml /opt/cribl/local/cribl/pipelines/datatap_generate/

# Restart Cribl
systemctl restart cribl    # or: /opt/cribl/bin/cribl restart
```

### Distributed (Leader + Workers)

Add the files to your Cribl config git repo:

```bash
# In your Cribl config repo, under the target worker group:
cp -r pack/default/data/samples/datatap_*.json groups/<worker-group>/data/samples/
cp pack/default/cribl/samples.yml groups/<worker-group>/local/cribl/samples.yml
cp pack/default/cribl/inputs_standalone.yml groups/<worker-group>/local/cribl/inputs.yml
mkdir -p groups/<worker-group>/local/cribl/pipelines/datatap_generate
cp pack/default/cribl/pipelines/datatap_generate/conf.yml groups/<worker-group>/local/cribl/pipelines/datatap_generate/

git add -A && git commit -m "Add DataTap" && git push
```

Leader deploys to workers automatically.

## After Install

Open your Cribl UI and go to **Data > Sources > Datagen**.

You'll see 15 source categories. `datatap-top10` is already enabled and streaming 10 events/sec of mixed enterprise data (PAN firewall, syslog, WinEventLog, CrowdStrike, Okta, Cisco ASA, CloudTrail, FortiGate, DNS, Kubernetes).

Enable any other category you need:

| Source | What it streams | Default EPS |
|--------|----------------|-------------|
| **datatap-top10** | 10 core enterprise sourcetypes | 10 |
| **datatap-prometheus** | High-cardinality Prometheus metrics | 100 |
| **datatap-metrics** | Prometheus + StatsD + Graphite + InfluxDB + CloudWatch + OTel | 100 |
| **datatap-security** | PAN, WinEventLog, CrowdStrike, Okta, ASA, CloudTrail + 6 more | 10 |
| **datatap-network** | PAN, ASA, FortiGate, Check Point, pfSense, NetFlow, Zeek, Suricata | 10 |
| **datatap-endpoint** | CrowdStrike, SentinelOne, Carbon Black, Defender, Cortex XDR, Wazuh, Elastic | 10 |
| **datatap-identity** | Okta, Duo, Azure AD, Auth0, CyberArk, BeyondTrust | 10 |
| **datatap-cloud-aws** | CloudTrail, GuardDuty, VPC Flow, Lambda, WAF, Config, SecurityHub, Route53 | 10 |
| **datatap-cloud-azure** | AAD Sign-in, Activity, NSG Flow, Firewall, Key Vault, O365 | 10 |
| **datatap-cloud-gcp** | Audit, Firewall, Logging | 10 |
| **datatap-o11y** | Prometheus, OTel, Jaeger, Log4j, Pino, K8s, Docker, Sentry | 10 |
| **datatap-devops** | K8s audit/events, Jenkins, GitLab, ArgoCD, Terraform, Docker | 10 |
| **datatap-applog** | Java Log4j, Python, Node Pino, Go slog, .NET, Apache, Nginx | 10 |
| **datatap-scenario-bruteforce** | Correlated attack chain with consistent attacker IP | 10 |
| **datatap-scenario-normalday** | Mixed baseline enterprise traffic | 10 |

To change volume, click any source and adjust **Events per second**.

## Stream Your Own Data

DataTap can stream any data you give it — not just the built-in sourcetypes.

### Zero-config (paste and go)

1. Create a sample: **Knowledge > Samples > Add Sample**
2. Paste a few real events from your app
3. Create a datagen source: **Data > Sources > Datagen > Add Source**
4. Set pipeline to `datatap_generate`, pick your sample, set EPS
5. Enable and save

DataTap automatically randomizes IPs, timestamps, and UUIDs in your events while keeping the structure and business fields intact.

### Template mode (full control)

Create a sample with a DataTap trigger event:

```json
[{"_raw":"{\"_datatap\":true,\"sourcetype\":\"myapp\",\"template\":\"t|{T} {H} myapp user={U} action={S:login,logout,purchase} status={S:200,400,500} ip={I}\"}","_time":1}]
```

Available tokens: `{I}` IP, `{U}` username, `{T}` timestamp, `{S:a,b,c}` pick one, `{N:1-100}` number range, `{ID}` UUID, `{H}` hostname, `{E}` email, `{HX:16}` hex, `{NM}` full name, `{DOM}` domain.

## Requirements

- Cribl Stream 4.0.0+
- Docker (for the install script) or filesystem access (for manual install)
- No other dependencies

## License

(c) DataDay Technology Solutions
