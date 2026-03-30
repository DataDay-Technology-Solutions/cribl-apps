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
