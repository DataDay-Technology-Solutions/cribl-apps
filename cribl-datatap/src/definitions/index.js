'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Sourcetype-to-filename mapping.
 * Maps sourcetype identifiers used in scenarios/CLI to their
 * corresponding definition JSON files on disk.
 */
const SOURCETYPE_MAP = {
  'pan:traffic':                 'palo-alto-traffic.json',
  'palo-alto-traffic':           'palo-alto-traffic.json',
  'WinEventLog:Security':        'windows-security.json',
  'windows-security':            'windows-security.json',
  'wineventlog:security':        'windows-security.json',
  'syslog':                      'syslog-rfc5424.json',
  'syslog-rfc5424':              'syslog-rfc5424.json',
  'crowdstrike:falcon:event':    'crowdstrike-falcon.json',
  'crowdstrike-falcon':          'crowdstrike-falcon.json',
  'okta:system':                 'okta-system-log.json',
  'okta-system-log':             'okta-system-log.json',
  'cisco:asa':                   'cisco-asa.json',
  'cisco-asa':                   'cisco-asa.json',
  'fortigate:traffic':           'fortinet-fortigate.json',
  'fortinet-fortigate':          'fortinet-fortigate.json',
  'checkpoint:firewall':         'checkpoint-firewall.json',
  'checkpoint-firewall':         'checkpoint-firewall.json',
  'juniper:srx':                 'juniper-srx.json',
  'juniper-srx':                 'juniper-srx.json',
  'aws:cloudwatchlogs:vpcflow':  'aws-vpc-flow.json',
  'aws-vpc-flow':                'aws-vpc-flow.json',
  'zscalernss-web':              'zscaler-zia-web.json',
  'zscaler-zia-web':             'zscaler-zia-web.json',
  'zscalernss-fw':               'zscaler-zia-fw.json',
  'zscaler-zia-fw':              'zscaler-zia-fw.json',
  'aws:cloudtrail':              'aws-cloudtrail.json',
  'aws-cloudtrail':              'aws-cloudtrail.json',
  'azure:aad:signin':            'azure-activity.json',
  'azure-activity':              'azure-activity.json',
  'google:gcp:audit':            'gcp-audit.json',
  'gcp-audit':                   'gcp-audit.json',
  'azure:nsg:flow':              'azure-nsg-flow.json',
  'azure-nsg-flow':              'azure-nsg-flow.json',
  'duo:authentication':          'duo-auth.json',
  'duo-auth':                    'duo-auth.json',
  'ms:defender:endpoint':        'microsoft-defender.json',
  'microsoft-defender':          'microsoft-defender.json',
  'proofpoint:tap':              'proofpoint-email.json',
  'proofpoint-email':            'proofpoint-email.json',
  'sentinelone:threat':          'sentinelone-threat.json',
  'sentinelone-threat':          'sentinelone-threat.json',
  'carbonblack:defense':         'carbon-black-defense.json',
  'carbon-black-defense':        'carbon-black-defense.json',
  'dns:query':                   'dns-query.json',
  'dns-query':                   'dns-query.json',
  'squid:access':                'squid-proxy.json',
  'squid-proxy':                 'squid-proxy.json',
  'linux:auditd':                'linux-auditd.json',
  'linux-auditd':                'linux-auditd.json',
  'qualys:hostDetection':        'qualys-vuln.json',
  'qualys-vuln':                 'qualys-vuln.json',
  'cloudflare:waf':              'cloudflare-waf.json',
  'cloudflare-waf':              'cloudflare-waf.json',
};

const DEFINITIONS_DIR = path.join(__dirname);

/** In-memory cache: filename -> parsed definition object */
const _cache = {};

/**
 * Resolve a sourcetype name to the definition filename.
 * Supports both canonical names (e.g. "pan:traffic") and
 * slug-style names (e.g. "palo-alto-traffic").
 *
 * @param {string} sourcetype
 * @returns {string|null} filename or null if not mapped
 */
function _resolveFilename(sourcetype) {
  // Exact match
  if (SOURCETYPE_MAP[sourcetype]) {
    return SOURCETYPE_MAP[sourcetype];
  }
  // Case-insensitive match
  const lower = sourcetype.toLowerCase();
  for (const key of Object.keys(SOURCETYPE_MAP)) {
    if (key.toLowerCase() === lower) {
      return SOURCETYPE_MAP[key];
    }
  }
  // Try as a direct filename (with or without .json)
  const candidate = sourcetype.endsWith('.json') ? sourcetype : sourcetype + '.json';
  const candidatePath = path.join(DEFINITIONS_DIR, candidate);
  if (fs.existsSync(candidatePath)) {
    return candidate;
  }
  return null;
}

/**
 * Load a definition JSON file by sourcetype name.
 *
 * @param {string} sourcetype - e.g. "pan:traffic", "windows-security", "syslog"
 * @returns {object} The parsed definition object
 * @throws {Error} If sourcetype is unknown or file cannot be read
 */
function loadDefinition(sourcetype) {
  const filename = _resolveFilename(sourcetype);
  if (!filename) {
    throw new Error(`Unknown sourcetype: "${sourcetype}". Available: ${listDefinitions().join(', ')}`);
  }

  // Return cached if available
  if (_cache[filename]) {
    return _cache[filename];
  }

  const filePath = path.join(DEFINITIONS_DIR, filename);
  if (!fs.existsSync(filePath)) {
    throw new Error(`Definition file not found: ${filePath}`);
  }

  const raw = fs.readFileSync(filePath, 'utf8');
  const definition = JSON.parse(raw);

  // Store in cache
  _cache[filename] = definition;

  return definition;
}

/**
 * Get a cached definition. Returns null if not yet loaded.
 *
 * @param {string} sourcetype
 * @returns {object|null}
 */
function getDefinition(sourcetype) {
  const filename = _resolveFilename(sourcetype);
  if (!filename) return null;
  return _cache[filename] || null;
}

/**
 * List all available sourcetype definitions.
 * Returns canonical sourcetype names (the "sourcetype" field inside each JSON).
 *
 * @returns {string[]}
 */
function listDefinitions() {
  const files = fs.readdirSync(DEFINITIONS_DIR).filter(f => f.endsWith('.json'));
  const sourcetypes = [];

  for (const file of files) {
    try {
      const filePath = path.join(DEFINITIONS_DIR, file);
      const raw = fs.readFileSync(filePath, 'utf8');
      const def = JSON.parse(raw);
      if (def.sourcetype) {
        sourcetypes.push(def.sourcetype);
      }
    } catch (_) {
      // Skip files that fail to parse
    }
  }

  return sourcetypes;
}

/**
 * Clear the definition cache. Useful for testing or reloading.
 */
function clearCache() {
  for (const key of Object.keys(_cache)) {
    delete _cache[key];
  }
}

/**
 * Get the sourcetype-to-filename mapping.
 * @returns {object}
 */
function getSourcetypeMap() {
  return Object.assign({}, SOURCETYPE_MAP);
}

module.exports = {
  loadDefinition,
  getDefinition,
  listDefinitions,
  clearCache,
  getSourcetypeMap,
  DEFINITIONS_DIR,
};
