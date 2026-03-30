# Cribl DataTap (CDT) — Product Spec

## What It Is
On-demand data streaming pack for Cribl. Generates production-realistic, high-uniqueness streaming data for any sourcetype — without needing real customer data.

## The Problem
- Pack builders (like Nth Degree with Zscaler) can't get real streaming data to develop packs
- Customers won't share data (privacy, legal, effort)
- Cribl's built-in Datagen only replays basic templates (apache_common, syslog) with low uniqueness and no correlation
- Cribl themselves couldn't get customers to stream data when Nth Degree asked

## 3-Tier Strategy

### Tier 1: DataTap Lite (FREE — Cribl Innovators group growth engine)
- 3-5 basic sourcetypes (syslog, apache, basic Windows events)
- Limited EPS, no scenario modes, no correlation
- Free to Cribl Innovators members
- Purpose: drive massive group growth. Every Cribl admin needs test data.

### Tier 2: DataTap Premium (PAID)
- 30+ sourcetypes (Palo Alto, CrowdStrike, AWS CloudTrail, Azure AD, Cisco ASA, O365, Okta, Zscaler, etc.)
- High cardinality randomization (unique IPs, users, hosts, GeoIP every event)
- Scenario modes (brute force, data exfil, insider threat, normal business day)
- Cross-sourcetype correlation (same user/IP across Okta -> Palo Alto -> Windows -> CrowdStrike)
- Unlimited EPS (10 to 10,000+)
- Target: MSSPs, training academies (like Kenneth/ECA), pack builders, SOC training

### Tier 3: DataTap Embedded (integrated into every DataDay app/pack)
- Small-scale DataTap integration in each Cribl pack and Splunk app
- "Generate demo data" button ships with every product
- User installs pack -> clicks generate -> sees it working in 30 seconds
- No real data source needed, no IT approval, no production env
- Embedded version generates ONLY data relevant to that specific app's use case
- Frictionless first experience for every DataDay product

## Architecture (Template Engine, NOT Template Library — Eliminates Bloat)

### Sourcetype Definition Files (~2-5KB each, JSON/YAML)
- Define event schema/structure for each sourcetype (field names, types, delimiters, format)
- Define value ranges per field (IP CIDR ranges, username pools, hostname patterns, severity levels, action types)
- Define correlation rules (if firewall deny -> next event should be retry or different port scan)
- Does NOT contain actual events — just the blueprint

### Shared Generation Engine (single, reusable across all sourcetypes)
- Reads definition files
- Generates events on the fly using randomization:
  - IPs: random within configurable CIDR ranges, weighted distribution (80% internal, 20% external)
  - Usernames/hostnames: algorithmic patterns (first.last, adjective-noun-number) or configurable pools
  - Timestamps: realistic jitter, bursts, quiet periods, business-hours weighting
  - Session/transaction IDs: UUID generation, guaranteed unique per stream
  - Payloads: randomized file paths, URLs, user agents, HTTP response codes with realistic distribution
  - GeoIP: realistic lat/long per IP range, mapped to countries/cities
  - Hashes: randomized SHA256/MD5, with option to reuse across correlated events
- Handles correlation logic across sourcetypes
- EPS control knob

### Scenario Correlation Engine
When user selects a scenario (e.g., "Simulate brute force attack"), the engine generates a correlated story:
1. Okta: 47 failed logins for user jsmith from IP 203.0.113.47 over 12 minutes
2. Palo Alto: Same IP hitting VPN gateway with multiple auth attempts
3. Windows Security: Event ID 4625 (failed logon) for jsmith on domain controller
4. CrowdStrike: Detection alert for credential stuffing from endpoint WKS-FINANCE-12
5. Then success: Okta login succeeds, VPN session established, lateral movement begins

Same IPs, same usernames, same timestamps — correlated across sourcetypes.

### Pack Size
- Each sourcetype definition: ~2-5KB
- 30 sourcetypes: ~100-150KB total
- Generation engine: ~50-100KB JavaScript
- Total pack: <500KB. No bloat.

## vs Cribl Datagen

| Feature | Cribl Datagen | Cribl DataTap |
|---------|--------------|---------------|
| Templates | Handful (apache, syslog) | 30+ sourcetypes out of the box |
| Uniqueness | Replays same events, only timestamps change | High-cardinality randomization — unique IPs, users, hostnames, GeoIP every event |
| Correlation | None — events are independent | Scenario modes — correlated event chains across sourcetypes |
| Use case | Test pipeline config / troubleshooting | Build packs, load test, train SOC analysts, demo products |
| Setup | Create your own templates from samples | Pick sourcetype, pick scenario, set EPS, go |
| Target user | Cribl admin troubleshooting | Pack builders, MSSPs, training academies, demo environments |

## MVP Build Plan
- Generation engine (core randomization + EPS control): 3-4 sessions
- First 5 sourcetype definitions (Palo Alto, Windows, Syslog, CrowdStrike, Okta): 2-3 sessions
- Correlation engine (cross-sourcetype story linking): 3-4 sessions
- First 2 scenario modes (brute force, normal day): 2 sessions
- Adding new sourcetypes after engine built: ~1 session per 5
- Total MVP: ~12 build sessions

## Target Users
- Pack builders (solves the Nth Degree problem)
- MSSPs needing demo/test environments
- Training academies (Kenneth/ECA — students get realistic data without production env)
- Demo environments for sales
- SOC analyst training
- Load testing Cribl deployments

## Demo Angle
"No customers? No data? No problem. Watch me spin up production-realistic Palo Alto + CrowdStrike + Windows + Okta streams in 30 seconds. Watch a correlated brute force attack unfold across all four sourcetypes in real time. Build your pack, test your pipeline, train your team — without waiting on anyone."

## Notion Reference
- Page ID: 333235c8-f969-813b-808a-e06c8757af31
- Parent DB: LI Content Calendar (data source: 2e7235c8-f969-80fc-a2b0-000b9267a39f)
- URL: https://www.notion.so/333235c8f969813b808ae06c8757af31
