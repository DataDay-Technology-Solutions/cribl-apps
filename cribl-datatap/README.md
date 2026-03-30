# Cribl DataTap

Production-realistic streaming data generator for security, observability, and IT operations pipelines.

## Features

- **5 sourcetype definitions** covering firewall, endpoint, identity, syslog, and EDR data
- **4 attack/activity scenarios** with multi-phase correlated event generation
- **Streaming mode** with configurable events-per-second and duration controls
- **Scenario engine** that produces correlated events across multiple sourcetypes using shared actors
- **Multiple output formats**: raw log lines, JSON, NDJSON, CSV
- **Zero external dependencies** -- runs on Node.js 18+ with nothing to install
- **Pipe-friendly** -- event data goes to stdout, stats and status go to stderr
- **ANSI-colored CLI** with live stats, phase transitions, and helpful error messages

## Quick Start

```bash
# Install (from source)
git clone <repo-url> && cd DataTap && npm link

# Generate 10 Palo Alto firewall log lines
datatap generate pan:traffic -n 10

# Stream syslog events at 100 eps for 30 seconds
datatap stream syslog --eps 100 -d 30

# Run a brute-force attack scenario at 10x speed
datatap scenario brute-force --time-scale 10 --verbose
```

## Usage

### Generate Events

```bash
# Single event (raw format)
datatap generate pan:traffic

# Multiple events as pretty-printed JSON
datatap generate okta:system -n 5 --format json --pretty

# CSV output for spreadsheet import
datatap generate syslog -n 100 --format csv > events.csv
```

### Stream Events

```bash
# Stream at default 10 eps (Ctrl+C to stop)
datatap stream pan:traffic

# Multiple sourcetypes, 50 eps, for 2 minutes
datatap stream syslog okta:system pan:traffic --eps 50 -d 120

# NDJSON to file for pipeline ingestion
datatap stream crowdstrike-falcon --format ndjson -o events.jsonl
```

### Run Scenarios

```bash
# Run with live phase output
datatap scenario brute-force --verbose

# Speed up 10x for quick testing
datatap scenario data-exfil --time-scale 10 --eps 100

# Quiet mode -- just the events
datatap scenario insider-threat --format ndjson -o scenario.jsonl
```

### List and Inspect

```bash
# List everything
datatap list

# List just sourcetypes or scenarios
datatap list sourcetypes
datatap list scenarios

# Detailed info about a sourcetype
datatap info pan:traffic
datatap info okta:system
```

## Sourcetypes

| Sourcetype | Vendor | Description |
|---|---|---|
| `pan:traffic` | Palo Alto Networks | PAN-OS firewall traffic logs (CSV) |
| `okta:system` | Okta | Okta System Log events (JSON) |
| `WinEventLog:Security` | Microsoft | Windows Security Event Log (XML) |
| `syslog` | Generic | RFC 5424 syslog messages |
| `crowdstrike:falcon:event` | CrowdStrike | Falcon EDR events (JSON) |

Each sourcetype supports slug-style aliases (e.g., `palo-alto-traffic`, `windows-security`, `crowdstrike-falcon`, `okta-system-log`, `syslog-rfc5424`).

## Scenarios

| Scenario | Description |
|---|---|
| `brute-force` | Credential stuffing attack with lateral movement |
| `normal-day` | Baseline enterprise traffic with business-hour patterns |
| `data-exfil` | Data exfiltration from reconnaissance through outbound transfer |
| `insider-threat` | Malicious insider with privilege escalation and anti-forensics |

Scenarios generate correlated events across multiple sourcetypes, using shared actor identities (IPs, usernames, hostnames) that thread through the entire attack narrative.

## Architecture

```
src/
  cli.js              CLI entry point (zero-dependency arg parsing)
  index.js            Public API (DataTap class)
  definitions/        Sourcetype definition JSON files
    index.js           Definition loader and registry
    *.json             One file per sourcetype
  engine/
    generator.js       Core event generation engine
    correlator.js      Cross-event correlation context
    scheduler.js       Timing and EPS control
    randomizers/       Field-type randomizers (IP, timestamp, enum, etc.)
  scenarios/
    index.js           Scenario registry
    *.js               One file per scenario
```

### How It Works

1. **Definitions** describe the schema for each sourcetype: fields, types, weights, templates, and variants
2. **Randomizers** produce realistic field values: IPs in proper CIDRs, weighted enums, timestamps with jitter
3. **The generator** combines definitions and randomizers to produce complete events
4. **The correlator** maintains shared actor state so events across sourcetypes reference the same IPs, users, and hosts
5. **The scheduler** controls event timing to hit target EPS rates
6. **Scenarios** orchestrate multi-phase sequences with phase-specific EPS multipliers and sourcetype mixes

## Programmatic API

```js
const DataTap = require('cribl-datatap');

// Generate a single event
const tap = new DataTap();
const event = tap.generate('pan:traffic');
console.log(event.raw);

// Stream with callbacks
const tap = new DataTap({
  eps: 50,
  onEvent: (event) => console.log(event.raw),
});
tap.stream(['syslog', 'okta:system'], { duration: 60 });

// Run a scenario
const tap = new DataTap({ correlate: true });
tap.runScenario('brute-force', {
  eps: 25,
  timeScale: 10,
  onEvent: (event) => sendToSIEM(event),
  onPhaseChange: (phase) => console.log(`Phase: ${phase.name}`),
});

// Static helpers
console.log(DataTap.listSourcetypes());
console.log(DataTap.listScenarios());
```

## Contributing

Contributions are welcome. To add a new sourcetype:

1. Create a JSON definition in `src/definitions/`
2. Register the sourcetype mapping in `src/definitions/index.js`
3. Add test coverage in `tests/`

To add a new scenario:

1. Create a scenario module in `src/scenarios/`
2. Register it in `src/scenarios/index.js`
3. Add test coverage in `tests/`

## License

UNLICENSED - Proprietary
