# DataTap Pack for Cribl Stream

On-demand production-realistic streaming data generation for Cribl Stream. Generates high-uniqueness events across 5 sourcetypes with realistic field distributions, weighted variants, and cross-field consistency.

## Supported Sourcetypes

| Sourcetype | Vendor | Format | Description |
|---|---|---|---|
| `pan:traffic` | Palo Alto Networks | CSV | PAN-OS firewall traffic logs |
| `syslog` | Generic | RFC 5424 | Syslog messages (SSH, CRON, systemd, nginx, etc.) |
| `WinEventLog:Security` | Microsoft | XML | Windows Security events (4624, 4625, 4672, 4688, etc.) |
| `crowdstrike:falcon:event` | CrowdStrike | JSON | Falcon EDR events (detections, process, network, DNS) |
| `okta:system` | Okta | JSON | Okta System Log (login, SSO, MFA, lockout, policy) |

## Installation

1. In Cribl Stream, go to **Packs** > **Add New** > **Import from File**
2. Upload the pack archive or clone this directory into your Cribl packs folder
3. The pack ID is `cribl-datatap`

## Quick Start

### Step 1: Create a Datagen Source

1. Go to **Sources** > **Datagen**
2. Create a new Datagen source
3. Select one of the DataTap sample files:
   - `datatap_pan_traffic.log` -- Palo Alto firewall traffic
   - `datatap_syslog.log` -- RFC 5424 syslog
   - `datatap_windows_security.log` -- Windows Security Event Log
   - `datatap_crowdstrike.log` -- CrowdStrike Falcon EDR
   - `datatap_okta.log` -- Okta System Log
   - `datatap_all_sources.log` -- Mixed stream of all 5 sourcetypes
4. Set the event generation interval (e.g., 1 event per second)

### Step 2: Attach the Pipeline

1. Go to **Routes** or the Datagen source settings
2. Attach the `datatap_generate` pipeline to your Datagen source
3. This pipeline intercepts the trigger events and replaces them with rich, realistic events

### Step 3: Route to a Destination

Send the generated events to any Cribl destination: Splunk, Elasticsearch, S3, or anything else.

## How It Works

The pack uses a two-stage approach:

1. **Datagen trigger events** -- Minimal JSON stubs that tell the engine which sourcetype to generate. These use Cribl's `__TIMESTAMP__` token for timing.

2. **Pipeline Code function** -- A Code function in the `datatap_generate` pipeline intercepts each trigger event, reads its `sourcetype` field, and calls the DataTap engine to generate a fully-formed event. The trigger event's `_raw` is replaced with the generated event.

The DataTap engine (bundled in `lib/datatap.js`) uses:
- **Weighted random distributions** for realistic field value selection
- **Variant systems** for event subtypes (e.g., Windows Event IDs 4624/4625/4672/4688)
- **Procedural generators** for infinite uniqueness (hostnames, serial numbers, names)
- **CIDR-aware IP generation** with internal/external weighting
- **Format-specific renderers** for CSV, XML, RFC 5424 syslog, and JSON

## Sample Files

Located in `default/data/samples/`:

| File | Description |
|---|---|
| `datatap_pan_traffic.log` | Single-line trigger for Palo Alto traffic |
| `datatap_syslog.log` | Single-line trigger for syslog |
| `datatap_windows_security.log` | Single-line trigger for Windows Security |
| `datatap_crowdstrike.log` | Single-line trigger for CrowdStrike Falcon |
| `datatap_okta.log` | Single-line trigger for Okta System Log |
| `datatap_all_sources.log` | 5-line trigger file for mixed-source streaming |

## Pipeline

### datatap_generate

Located in `default/cribl/pipelines/datatap_generate/conf.yml`

Contains a single Code function that:
1. Filters for events with `_datatap === true`
2. Loads the DataTap engine from the pack's `lib/` directory
3. Generates a production-realistic event based on the `sourcetype` field
4. Replaces `_raw`, `_time`, `sourcetype`, and `source` on the event
5. Falls back to error annotation if generation fails

## Requirements

- Cribl Stream 4.0.0 or later
- No external dependencies (engine is fully self-contained)

## License

(c) DataDay Technology Solutions
