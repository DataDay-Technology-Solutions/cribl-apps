# Changelog

All notable changes to Cribl DataTap will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.1.0] - 2026-03-30

### Added
- Initial project scaffolding and architecture
- CLI interface with zero external dependencies (`generate`, `stream`, `scenario`, `list`, `info` commands)
- Main library entry point with `DataTap` class exposing `generate()`, `stream()`, `runScenario()`, and `stop()`
- 5 sourcetype definitions: `pan:traffic`, `okta:system`, `WinEventLog:Security`, `syslog`, `crowdstrike:falcon:event`
- 4 scenario definitions: `brute-force`, `normal-day`, `data-exfil`, `insider-threat`
- Sourcetype definition loader with alias resolution and caching
- Scenario registry with lookup and listing APIs
- Field randomizer modules: network, identity, temporal, security, geo
- Multiple output formats: raw, JSON, NDJSON, CSV
- ANSI-colored CLI output with live streaming stats on stderr
- Pipe-friendly design (event data on stdout, status on stderr)
- Graceful shutdown handling (SIGINT/SIGTERM)
