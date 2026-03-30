#!/usr/bin/env node
'use strict';

/**
 * DataTap CLI
 *
 * Zero-dependency command-line interface for generating production-realistic
 * streaming data. All argument parsing is done manually.
 *
 * Usage:
 *   datatap generate <sourcetype> [options]
 *   datatap stream <sourcetypes...> [options]
 *   datatap scenario <name> [options]
 *   datatap list [type]
 *   datatap info <sourcetype>
 *   datatap --help
 *   datatap --version
 */

// ---------------------------------------------------------------------------
// ANSI color helpers (zero dependencies)
// ---------------------------------------------------------------------------
const isTTY = process.stderr.isTTY;

const color = {
  reset:   (s) => isTTY ? `\x1b[0m${s}\x1b[0m` : s,
  bold:    (s) => isTTY ? `\x1b[1m${s}\x1b[0m` : s,
  dim:     (s) => isTTY ? `\x1b[2m${s}\x1b[0m` : s,
  red:     (s) => isTTY ? `\x1b[31m${s}\x1b[0m` : s,
  green:   (s) => isTTY ? `\x1b[32m${s}\x1b[0m` : s,
  yellow:  (s) => isTTY ? `\x1b[33m${s}\x1b[0m` : s,
  blue:    (s) => isTTY ? `\x1b[34m${s}\x1b[0m` : s,
  cyan:    (s) => isTTY ? `\x1b[1;36m${s}\x1b[0m` : s,
  gray:    (s) => isTTY ? `\x1b[90m${s}\x1b[0m` : s,
  white:   (s) => isTTY ? `\x1b[37m${s}\x1b[0m` : s,
  magenta: (s) => isTTY ? `\x1b[35m${s}\x1b[0m` : s,
};

// ---------------------------------------------------------------------------
// Lazy-load modules (so --help / --version are instant)
// ---------------------------------------------------------------------------
let _definitions = null;
let _scenarios = null;

function definitions() {
  if (!_definitions) _definitions = require('./definitions');
  return _definitions;
}

function scenarios() {
  if (!_scenarios) _scenarios = require('./scenarios');
  return _scenarios;
}

// ---------------------------------------------------------------------------
// Package metadata
// ---------------------------------------------------------------------------
function getVersion() {
  try {
    const pkg = require('../package.json');
    return pkg.version || '0.1.0';
  } catch (_) {
    return '0.1.0';
  }
}

// ---------------------------------------------------------------------------
// Argument parser
// ---------------------------------------------------------------------------
function parseArgs(argv) {
  const args = argv.slice(2);
  const result = {
    command: null,
    positional: [],
    flags: {},
  };

  let i = 0;
  while (i < args.length) {
    const arg = args[i];

    if (arg === '--help' || arg === '-h') {
      result.flags.help = true;
      i++;
    } else if (arg === '--version' || arg === '-V') {
      result.flags.version = true;
      i++;
    } else if (arg === '--pretty') {
      result.flags.pretty = true;
      i++;
    } else if (arg === '--verbose' || arg === '-v') {
      result.flags.verbose = true;
      i++;
    } else if (arg.startsWith('--') || (arg.startsWith('-') && arg.length === 2 && !isPositional(arg))) {
      // Named flag with value
      const key = normalizeFlag(arg);
      const next = args[i + 1];
      if (next !== undefined && !next.startsWith('-')) {
        result.flags[key] = next;
        i += 2;
      } else {
        result.flags[key] = true;
        i++;
      }
    } else {
      // Positional argument
      if (result.command === null) {
        result.command = arg;
      } else {
        result.positional.push(arg);
      }
      i++;
    }
  }

  return result;
}

function isPositional(arg) {
  // Negative numbers are positional
  return /^-\d/.test(arg);
}

function normalizeFlag(flag) {
  // --time-scale -> timeScale, -n -> n, --eps -> eps
  const stripped = flag.replace(/^-+/, '');
  return stripped.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
}

// ---------------------------------------------------------------------------
// Help text
// ---------------------------------------------------------------------------
function printHelp() {
  const v = getVersion();
  process.stderr.write(`
${color.cyan('DataTap')} ${color.dim(`v${v}`)} - Production-realistic streaming data generator

${color.bold('USAGE')}
  datatap <command> [options]

${color.bold('COMMANDS')}
  ${color.yellow('generate')} <sourcetype>       Generate event(s) for a sourcetype
  ${color.yellow('stream')}   <sourcetypes...>   Stream continuous events to stdout
  ${color.yellow('scenario')} <name>             Run a predefined attack/activity scenario
  ${color.yellow('list')}     [type]             List available sourcetypes or scenarios
  ${color.yellow('info')}     <sourcetype>       Show details about a sourcetype definition

${color.bold('GENERATE OPTIONS')}
  --count, -n     Number of events to generate  ${color.dim('(default: 1)')}
  --format        Output format: raw, json, csv  ${color.dim('(default: raw)')}
  --pretty        Pretty-print JSON output

${color.bold('STREAM OPTIONS')}
  --eps           Events per second              ${color.dim('(default: 10)')}
  --duration, -d  Duration in seconds            ${color.dim('(default: 0 = infinite)')}
  --format        Output format: raw, json, ndjson  ${color.dim('(default: raw)')}
  --output, -o    Output file path               ${color.dim('(default: stdout)')}

${color.bold('SCENARIO OPTIONS')}
  --eps           Base events per second          ${color.dim('(default: 10)')}
  --time-scale    Speed multiplier               ${color.dim('(default: 1)')}
  --format        Output format: raw, json, ndjson  ${color.dim('(default: raw)')}
  --output, -o    Output file path               ${color.dim('(default: stdout)')}
  --verbose, -v   Show phase transitions & stats

${color.bold('GLOBAL OPTIONS')}
  --help, -h      Show this help message
  --version, -V   Show version number

${color.bold('EXAMPLES')}
  ${color.dim('# Generate 5 Palo Alto firewall events')}
  datatap generate pan:traffic -n 5

  ${color.dim('# Stream syslog and Okta events at 50 eps for 60 seconds')}
  datatap stream syslog okta:system --eps 50 -d 60

  ${color.dim('# Run brute-force scenario at 10x speed')}
  datatap scenario brute-force --time-scale 10 --verbose

  ${color.dim('# Pipe JSON events to a file')}
  datatap stream pan:traffic --format ndjson -o events.json

  ${color.dim('# List all available sourcetypes')}
  datatap list sourcetypes

`);
}

function printCommandHelp(command) {
  switch (command) {
    case 'generate':
      process.stderr.write(`
${color.bold('datatap generate')} <sourcetype> [options]

Generate one or more events for a given sourcetype.

${color.bold('OPTIONS')}
  --count, -n     Number of events  ${color.dim('(default: 1)')}
  --format        raw, json, csv    ${color.dim('(default: raw)')}
  --pretty        Pretty-print JSON

${color.bold('EXAMPLES')}
  datatap generate pan:traffic
  datatap generate syslog -n 10 --format json --pretty
  datatap generate okta:system -n 3 --format csv

`);
      break;
    case 'stream':
      process.stderr.write(`
${color.bold('datatap stream')} <sourcetypes...> [options]

Stream continuous events to stdout. Multiple sourcetypes are round-robined.

${color.bold('OPTIONS')}
  --eps           Events per second   ${color.dim('(default: 10)')}
  --duration, -d  Seconds to run      ${color.dim('(default: 0 = infinite)')}
  --format        raw, json, ndjson   ${color.dim('(default: raw)')}
  --output, -o    Output file path    ${color.dim('(default: stdout)')}

${color.bold('EXAMPLES')}
  datatap stream syslog --eps 100 -d 30
  datatap stream pan:traffic okta:system --format ndjson

`);
      break;
    case 'scenario':
      process.stderr.write(`
${color.bold('datatap scenario')} <name> [options]

Run a predefined multi-phase scenario with correlated events.

${color.bold('OPTIONS')}
  --eps           Base events/second  ${color.dim('(default: 10)')}
  --time-scale    Speed multiplier    ${color.dim('(default: 1)')}
  --format        raw, json, ndjson   ${color.dim('(default: raw)')}
  --output, -o    Output file path    ${color.dim('(default: stdout)')}
  --verbose, -v   Show phase changes

${color.bold('EXAMPLES')}
  datatap scenario brute-force --verbose
  datatap scenario data-exfil --time-scale 10 --eps 50

`);
      break;
    default:
      printHelp();
  }
}

// ---------------------------------------------------------------------------
// Output formatting
// ---------------------------------------------------------------------------
function formatEvent(event, format, pretty) {
  switch (format) {
    case 'json':
      if (pretty) {
        return JSON.stringify(event, null, 2);
      }
      return JSON.stringify(event);

    case 'ndjson':
      return JSON.stringify(event);

    case 'csv': {
      if (!event || !event.fields) return '';
      const fields = event.fields;
      const keys = Object.keys(fields);
      const values = keys.map((k) => {
        const v = String(fields[k] || '');
        // Escape CSV values containing commas, quotes, or newlines
        if (v.includes(',') || v.includes('"') || v.includes('\n')) {
          return '"' + v.replace(/"/g, '""') + '"';
        }
        return v;
      });
      return values.join(',');
    }

    case 'raw':
    default:
      return event.raw || event._raw || JSON.stringify(event);
  }
}

// ---------------------------------------------------------------------------
// Stats tracker
// ---------------------------------------------------------------------------
class StatsTracker {
  constructor() {
    this.startTime = Date.now();
    this.totalEvents = 0;
    this.bySourcetype = {};
  }

  record(sourcetype) {
    this.totalEvents++;
    this.bySourcetype[sourcetype] = (this.bySourcetype[sourcetype] || 0) + 1;
  }

  format() {
    const elapsed = ((Date.now() - this.startTime) / 1000).toFixed(1);
    const eps = this.totalEvents / Math.max(parseFloat(elapsed), 0.1);
    const breakdown = Object.entries(this.bySourcetype)
      .map(([st, count]) => `${color.yellow(st)}: ${count}`)
      .join(', ');

    return color.gray(
      `[DataTap] ${elapsed}s | ${this.totalEvents} events | ${eps.toFixed(1)} eps | ${breakdown}`
    );
  }
}

// ---------------------------------------------------------------------------
// Output writer
// ---------------------------------------------------------------------------
function createWriter(outputPath) {
  if (outputPath && outputPath !== '-') {
    const fs = require('fs');
    const stream = fs.createWriteStream(outputPath, { flags: 'a' });
    return {
      write: (data) => stream.write(data + '\n'),
      close: () => stream.end(),
    };
  }
  return {
    write: (data) => process.stdout.write(data + '\n'),
    close: () => {},
  };
}

// ---------------------------------------------------------------------------
// Command: generate
// ---------------------------------------------------------------------------
function cmdGenerate(positional, flags) {
  if (positional.length === 0) {
    process.stderr.write(color.red('Error: sourcetype is required\n'));
    process.stderr.write(color.dim('Usage: datatap generate <sourcetype> [-n count] [--format raw|json|csv]\n\n'));
    printAvailableSourcetypes();
    process.exit(1);
  }

  const sourcetype = positional[0];
  const count = parseInt(flags.count || flags.n || '1', 10);
  const format = flags.format || 'raw';
  const pretty = !!flags.pretty;

  if (isNaN(count) || count < 1) {
    process.stderr.write(color.red('Error: --count must be a positive integer\n'));
    process.exit(1);
  }

  // Validate sourcetype
  try {
    definitions().loadDefinition(sourcetype);
  } catch (err) {
    process.stderr.write(color.red(`Error: ${err.message}\n\n`));
    printAvailableSourcetypes();
    process.exit(1);
  }

  // Lazy-load the generator
  let DataTapGenerator;
  try {
    ({ DataTapGenerator } = require('./engine/generator'));
  } catch (err) {
    process.stderr.write(color.red(`Error: Engine not available. ${err.message}\n`));
    process.stderr.write(color.dim('The engine module may still be building. Try again shortly.\n'));
    process.exit(1);
  }

  const generator = new DataTapGenerator();

  // Print CSV header if applicable
  if (format === 'csv' && count > 0) {
    try {
      const def = definitions().loadDefinition(sourcetype);
      if (def.fields) {
        const header = def.fields.map((f) => f.name).join(',');
        process.stdout.write(header + '\n');
      }
    } catch (_) {
      // Skip header if definition doesn't have fields
    }
  }

  for (let i = 0; i < count; i++) {
    const event = generator.generate(sourcetype);
    process.stdout.write(formatEvent(event, format, pretty) + '\n');
  }
}

// ---------------------------------------------------------------------------
// Command: stream
// ---------------------------------------------------------------------------
function cmdStream(positional, flags) {
  if (positional.length === 0) {
    process.stderr.write(color.red('Error: at least one sourcetype is required\n'));
    process.stderr.write(color.dim('Usage: datatap stream <sourcetypes...> [--eps 10] [-d 60]\n\n'));
    printAvailableSourcetypes();
    process.exit(1);
  }

  const sourcetypes = positional;
  const eps = parseFloat(flags.eps || '10');
  const duration = parseInt(flags.duration || flags.d || '0', 10);
  const format = flags.format || 'raw';
  const outputPath = flags.output || flags.o || null;

  if (isNaN(eps) || eps <= 0) {
    process.stderr.write(color.red('Error: --eps must be a positive number\n'));
    process.exit(1);
  }

  // Validate all sourcetypes
  for (const st of sourcetypes) {
    try {
      definitions().loadDefinition(st);
    } catch (err) {
      process.stderr.write(color.red(`Error: ${err.message}\n\n`));
      printAvailableSourcetypes();
      process.exit(1);
    }
  }

  // Load engine components
  let DataTapGenerator, EventScheduler;
  try {
    ({ DataTapGenerator } = require('./engine/generator'));
    ({ EventScheduler } = require('./engine/scheduler'));
  } catch (err) {
    process.stderr.write(color.red(`Error: Engine not available. ${err.message}\n`));
    process.stderr.write(color.dim('The engine module may still be building. Try again shortly.\n'));
    process.exit(1);
  }

  const generator = new DataTapGenerator();
  const writer = createWriter(outputPath);
  const stats = new StatsTracker();
  let eventIndex = 0;

  // Print startup banner
  process.stderr.write(
    color.cyan('\n  DataTap') +
    color.dim(` v${getVersion()}`) +
    color.white(' | Streaming ') +
    sourcetypes.map((s) => color.yellow(s)).join(', ') +
    color.white(` at ${color.bold(String(eps))} eps`) +
    (duration > 0 ? color.white(` for ${duration}s`) : color.dim(' (Ctrl+C to stop)')) +
    '\n\n'
  );

  // generatorFn: called by the scheduler to produce each event
  const generatorFn = () => {
    const sourcetype = sourcetypes[eventIndex % sourcetypes.length];
    eventIndex++;
    return generator.generate(sourcetype);
  };

  const scheduler = new EventScheduler({
    eps,
    onEvent: (event) => {
      stats.record(event.sourcetype || sourcetypes[(eventIndex - 1) % sourcetypes.length]);
      writer.write(formatEvent(event, format, false));
    },
  });

  // Stats reporting on stderr every 5 seconds
  const statsInterval = setInterval(() => {
    process.stderr.write('\r' + stats.format());
  }, 5000);

  // Duration timeout
  let durationTimer = null;
  if (duration > 0) {
    durationTimer = setTimeout(() => {
      shutdown();
    }, duration * 1000);
  }

  function shutdown() {
    scheduler.stop();
    clearInterval(statsInterval);
    if (durationTimer) clearTimeout(durationTimer);

    // Final stats
    process.stderr.write('\n' + stats.format() + '\n');
    process.stderr.write(color.green('\nDone.\n'));
    writer.close();
    process.exit(0);
  }

  // Graceful shutdown on SIGINT / SIGTERM
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  scheduler.start(generatorFn);
}

// ---------------------------------------------------------------------------
// Command: scenario
// ---------------------------------------------------------------------------
function cmdScenario(positional, flags) {
  if (positional.length === 0) {
    process.stderr.write(color.red('Error: scenario name is required\n'));
    process.stderr.write(color.dim('Usage: datatap scenario <name> [--eps 10] [--time-scale 1]\n\n'));
    printAvailableScenarios();
    process.exit(1);
  }

  const scenarioName = positional[0];
  const eps = parseFloat(flags.eps || '10');
  const timeScale = parseFloat(flags.timeScale || flags['time-scale'] || '1');
  const format = flags.format || 'raw';
  const outputPath = flags.output || flags.o || null;
  const verbose = !!flags.verbose || !!flags.v;

  // Validate scenario exists
  let scenario;
  try {
    scenario = scenarios().getScenario(scenarioName);
  } catch (err) {
    process.stderr.write(color.red(`Error: ${err.message}\n\n`));
    printAvailableScenarios();
    process.exit(1);
  }

  // Load engine components
  let DataTap;
  try {
    DataTap = require('./index');
  } catch (err) {
    process.stderr.write(color.red(`Error: Engine not available. ${err.message}\n`));
    process.stderr.write(color.dim('The engine module may still be building. Try again shortly.\n'));
    process.exit(1);
  }

  const writer = createWriter(outputPath);
  const stats = new StatsTracker();

  // Print startup banner
  process.stderr.write(
    color.cyan('\n  DataTap') +
    color.dim(` v${getVersion()}`) +
    color.white(' | Scenario: ') +
    color.cyan(color.bold(scenario.name)) +
    '\n' +
    color.dim(`  ${scenario.description}`) +
    '\n' +
    color.white(`  ${scenario.phases.length} phases | ${eps} eps base | ${timeScale}x speed`) +
    '\n\n'
  );

  const tap = new DataTap({
    eps,
    correlate: true,
    onEvent: (event, fmt) => {
      stats.record(event.sourcetype || 'unknown');
      writer.write(formatEvent(event, format, false));
    },
  });

  // Stats reporting on stderr every 5 seconds
  const statsInterval = setInterval(() => {
    process.stderr.write('\r' + stats.format());
  }, 5000);

  tap.runScenario(scenarioName, {
    eps,
    timeScale,
    format,
    onEvent: (event) => {
      stats.record(event.sourcetype || 'unknown');
      writer.write(formatEvent(event, format, false));
    },
    onPhaseChange: (phase, index, total) => {
      if (verbose) {
        const phaseSourcetypes = (phase.sourcetypes || []).map((s) => color.yellow(s)).join(', ');
        const durationDesc = phase.durationSec
          ? `${Math.round(phase.durationSec / timeScale)}s`
          : 'unknown duration';
        process.stderr.write(
          '\n' +
          color.cyan(`[DataTap] Phase ${index + 1}/${total}: `) +
          color.cyan(color.bold(phase.name || `phase-${index + 1}`)) +
          color.dim(` (${durationDesc})`) +
          (phaseSourcetypes ? color.white(` | Generating ${phaseSourcetypes}`) : '') +
          '\n'
        );
      }
    },
  });

  function shutdown() {
    tap.stop();
    clearInterval(statsInterval);
    process.stderr.write('\n' + stats.format() + '\n');
    process.stderr.write(color.green('\nScenario complete.\n'));
    writer.close();
    process.exit(0);
  }

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

// ---------------------------------------------------------------------------
// Command: list
// ---------------------------------------------------------------------------
function cmdList(positional, flags) {
  const type = (positional[0] || 'all').toLowerCase();

  if (!['all', 'sourcetypes', 'scenarios'].includes(type)) {
    process.stderr.write(color.red(`Error: unknown list type "${type}"\n`));
    process.stderr.write(color.dim('Valid types: sourcetypes, scenarios, all\n'));
    process.exit(1);
  }

  if (type === 'all' || type === 'sourcetypes') {
    process.stderr.write(color.bold('\nSourcetypes\n'));
    process.stderr.write(color.dim('─'.repeat(60)) + '\n');

    const defs = definitions();
    const sourcetypes = defs.listDefinitions();

    if (sourcetypes.length === 0) {
      process.stderr.write(color.dim('  No sourcetype definitions found.\n'));
    } else {
      for (const st of sourcetypes) {
        try {
          const def = defs.loadDefinition(st);
          process.stderr.write(
            '  ' +
            color.yellow(padRight(st, 28)) +
            color.dim(def.description || '') +
            '\n'
          );
        } catch (_) {
          process.stderr.write('  ' + color.yellow(st) + '\n');
        }
      }
    }
    process.stderr.write('\n');
  }

  if (type === 'all' || type === 'scenarios') {
    process.stderr.write(color.bold('Scenarios\n'));
    process.stderr.write(color.dim('─'.repeat(60)) + '\n');

    try {
      const scenarioList = scenarios().listScenarios();

      if (scenarioList.length === 0) {
        process.stderr.write(color.dim('  No scenarios found.\n'));
      } else {
        for (const s of scenarioList) {
          process.stderr.write(
            '  ' +
            color.cyan(padRight(s.name, 28)) +
            color.dim(s.description || '') +
            '\n' +
            '  ' +
            color.dim(padRight('', 28)) +
            color.dim(`${s.phaseCount} phases`) +
            '\n'
          );
        }
      }
    } catch (err) {
      process.stderr.write(color.dim(`  Error loading scenarios: ${err.message}\n`));
    }
    process.stderr.write('\n');
  }
}

// ---------------------------------------------------------------------------
// Command: info
// ---------------------------------------------------------------------------
function cmdInfo(positional, flags) {
  if (positional.length === 0) {
    process.stderr.write(color.red('Error: sourcetype is required\n'));
    process.stderr.write(color.dim('Usage: datatap info <sourcetype>\n\n'));
    printAvailableSourcetypes();
    process.exit(1);
  }

  const sourcetype = positional[0];
  let def;

  try {
    def = definitions().loadDefinition(sourcetype);
  } catch (err) {
    process.stderr.write(color.red(`Error: ${err.message}\n\n`));
    printAvailableSourcetypes();
    process.exit(1);
  }

  process.stderr.write('\n');
  process.stderr.write(color.cyan(color.bold(def.sourcetype)) + '\n');
  process.stderr.write(color.dim('─'.repeat(60)) + '\n');
  process.stderr.write(color.white('  Description:  ') + (def.description || 'N/A') + '\n');
  process.stderr.write(color.white('  Vendor:       ') + (def.vendor || 'N/A') + '\n');
  process.stderr.write(color.white('  Product:      ') + (def.product || 'N/A') + '\n');
  process.stderr.write(color.white('  Format:       ') + (def.format || 'N/A') + '\n');

  // Fields
  if (def.fields && def.fields.length > 0) {
    process.stderr.write('\n' + color.bold('  Fields') + color.dim(` (${def.fields.length})`) + '\n');
    process.stderr.write(color.dim('  ' + '─'.repeat(56)) + '\n');
    for (const field of def.fields) {
      const typeStr = color.dim(`[${field.type}]`);
      process.stderr.write(
        '    ' +
        color.yellow(padRight(field.name, 14)) +
        padRight(typeStr, 24) +
        formatFieldConfig(field) +
        '\n'
      );
    }
  }

  // Variants
  if (def.variants) {
    const variantNames = Object.keys(def.variants);
    process.stderr.write('\n' + color.bold('  Variants') + color.dim(` (${variantNames.length})`) + '\n');
    process.stderr.write(color.dim('  ' + '─'.repeat(56)) + '\n');
    for (const vName of variantNames) {
      const v = def.variants[vName];
      const weight = v.weight !== undefined ? color.dim(` (${(v.weight * 100).toFixed(0)}%)`) : '';
      process.stderr.write('    ' + color.magenta(padRight(vName, 18)) + weight + '\n');
    }
  }

  // Correlation hints
  if (def.correlationHints) {
    process.stderr.write('\n' + color.bold('  Correlation Hints') + '\n');
    process.stderr.write(color.dim('  ' + '─'.repeat(56)) + '\n');
    for (const [hint, field] of Object.entries(def.correlationHints)) {
      process.stderr.write('    ' + color.white(padRight(hint, 18)) + color.yellow(field) + '\n');
    }
  }

  // Template
  if (def.template) {
    process.stderr.write('\n' + color.bold('  Template') + '\n');
    process.stderr.write(color.dim('  ' + '─'.repeat(56)) + '\n');
    const tmpl = typeof def.template === 'string' ? def.template : JSON.stringify(def.template);
    // Truncate long templates
    const maxLen = 120;
    const display = tmpl.length > maxLen ? tmpl.substring(0, maxLen) + '...' : tmpl;
    process.stderr.write('    ' + color.dim(display) + '\n');
  }

  process.stderr.write('\n');
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function padRight(str, len) {
  // Strip ANSI for length calculation
  const stripped = str.replace(/\x1b\[[0-9;]*m/g, '');
  if (stripped.length >= len) return str;
  return str + ' '.repeat(len - stripped.length);
}

function formatFieldConfig(field) {
  const config = field.config || {};

  if (config.values && config.values.length > 0) {
    const preview = config.values.slice(0, 4).join(', ');
    const more = config.values.length > 4 ? ` +${config.values.length - 4} more` : '';
    return color.dim(preview + more);
  }

  if (config.pool && config.pool.length > 0) {
    const preview = config.pool.slice(0, 3).join(', ');
    const more = config.pool.length > 3 ? ` +${config.pool.length - 3} more` : '';
    return color.dim(preview + more);
  }

  if (config.min !== undefined && config.max !== undefined) {
    return color.dim(`${config.min} - ${config.max}`);
  }

  if (config.cidr) {
    return color.dim(config.cidr);
  }

  if (config.format) {
    return color.dim(config.format);
  }

  return '';
}

function printAvailableSourcetypes() {
  try {
    const sourcetypes = definitions().listDefinitions();
    process.stderr.write(color.white('Available sourcetypes:\n'));
    for (const st of sourcetypes) {
      process.stderr.write('  ' + color.yellow(st) + '\n');
    }
    process.stderr.write('\n');
  } catch (_) {
    // Silently fail if definitions can't load
  }
}

function printAvailableScenarios() {
  try {
    const scenarioList = scenarios().listScenarios();
    process.stderr.write(color.white('Available scenarios:\n'));
    for (const s of scenarioList) {
      process.stderr.write('  ' + color.cyan(s.name) + color.dim(`  ${s.description}`) + '\n');
    }
    process.stderr.write('\n');
  } catch (_) {
    // Silently fail
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
function main() {
  const parsed = parseArgs(process.argv);

  // Global flags
  if (parsed.flags.version) {
    process.stdout.write(getVersion() + '\n');
    process.exit(0);
  }

  if (parsed.flags.help && !parsed.command) {
    printHelp();
    process.exit(0);
  }

  if (parsed.flags.help && parsed.command) {
    printCommandHelp(parsed.command);
    process.exit(0);
  }

  if (!parsed.command) {
    printHelp();
    process.exit(0);
  }

  // Route to command handler
  try {
    switch (parsed.command) {
      case 'generate':
      case 'gen':
      case 'g':
        cmdGenerate(parsed.positional, parsed.flags);
        break;

      case 'stream':
      case 's':
        cmdStream(parsed.positional, parsed.flags);
        break;

      case 'scenario':
      case 'sc':
        cmdScenario(parsed.positional, parsed.flags);
        break;

      case 'list':
      case 'ls':
      case 'l':
        cmdList(parsed.positional, parsed.flags);
        break;

      case 'info':
      case 'i':
        cmdInfo(parsed.positional, parsed.flags);
        break;

      default:
        process.stderr.write(color.red(`Unknown command: "${parsed.command}"\n\n`));
        process.stderr.write(color.dim('Run "datatap --help" for usage information.\n'));
        process.exit(1);
    }
  } catch (err) {
    process.stderr.write(color.red(`\nError: ${err.message}\n`));
    if (process.env.DEBUG) {
      process.stderr.write(color.dim(err.stack + '\n'));
    }
    process.exit(1);
  }
}

main();
