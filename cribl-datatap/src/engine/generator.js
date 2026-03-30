'use strict';

const crypto = require('crypto');
const { loadDefinition } = require('../definitions');
const randomizers = require('./randomizers');

/**
 * Core event generation engine for DataTap.
 *
 * Reads sourcetype definitions, selects variants, generates field values
 * using the randomizer library, and renders events in CSV, XML,
 * syslog RFC 5424, and JSON formats.
 */
class DataTapGenerator {
  /**
   * @param {object} options
   * @param {number} [options.seed]  - Seed for deterministic output (testing/replay)
   * @param {object} [options.correlationContext] - CorrelationContext instance for shared state
   */
  constructor(options = {}) {
    this.seed = options.seed !== undefined ? options.seed : undefined;
    this.correlationContext = options.correlationContext || null;
    this._eventCounter = 0;
  }

  /**
   * Generate a single event for a sourcetype.
   *
   * @param {string} sourcetype - e.g. "pan:traffic", "okta:system"
   * @param {object} [overrides={}] - Field overrides from scenarios/correlation
   * @returns {{ raw: string, fields: object, sourcetype: string, timestamp: string }}
   */
  generate(sourcetype, overrides = {}) {
    const definition = loadDefinition(sourcetype);
    this._eventCounter++;

    // Select variant (if definition has variants)
    const { variantKey, variant, mergedFieldDefs } = this._selectVariant(definition);

    // Build the field context: resolve all field values
    const fields = this._generateAllFields(mergedFieldDefs, definition, variant, overrides);

    // Handle calculated fields
    this._applyCalculatedFields(fields, definition);

    // Render the raw event string
    const raw = this._renderEvent(definition, variant, variantKey, fields);

    // Extract timestamp from fields (use the first timestamp field found)
    let timestamp = null;
    for (const fDef of mergedFieldDefs) {
      if (fDef.type === 'timestamp' && fields[fDef.name] !== undefined) {
        timestamp = fields[fDef.name];
        break;
      }
    }
    if (!timestamp) {
      timestamp = new Date().toISOString();
    }

    // Track in correlation context if available
    if (this.correlationContext) {
      this.correlationContext.trackEvent({
        raw,
        fields,
        sourcetype: definition.sourcetype,
        timestamp,
      });
    }

    return {
      raw,
      fields,
      sourcetype: definition.sourcetype,
      timestamp,
    };
  }

  // ---------------------------------------------------------------------------
  // Variant selection
  // ---------------------------------------------------------------------------

  /**
   * Select a variant from the definition based on weights.
   * Returns the merged field definitions (base + variant).
   *
   * @param {object} definition
   * @returns {{ variantKey: string|null, variant: object|null, mergedFieldDefs: Array }}
   */
  _selectVariant(definition) {
    if (!definition.variants) {
      return {
        variantKey: null,
        variant: null,
        mergedFieldDefs: definition.fields || [],
      };
    }

    const variantKeys = Object.keys(definition.variants);
    const weights = variantKeys.map(k => definition.variants[k].weight || 1);

    const variantKey = randomizers.weightedChoice(variantKeys, weights, this._getSeed());
    const variant = definition.variants[variantKey];

    // Merge base fields with variant-specific fields
    const mergedFieldDefs = this._mergeFieldDefs(definition.fields || [], variant.fields || {});

    return { variantKey, variant, mergedFieldDefs };
  }

  /**
   * Merge base field definitions with variant field overrides.
   * Variant fields can be:
   *   - A string value (static override): { "EID": "4624" }
   *   - A field definition object: { "LT": { type: "enum", config: {...} } }
   *
   * @param {Array} baseFields - Array of field definition objects
   * @param {object} variantFields - Map of field name -> value or field def
   * @returns {Array} merged field definitions
   */
  _mergeFieldDefs(baseFields, variantFields) {
    // Start with copies of base fields
    const merged = baseFields.map(f => Object.assign({}, f));

    // Add/override variant fields
    for (const [name, value] of Object.entries(variantFields)) {
      const existing = merged.find(f => f.name === name);

      if (typeof value === 'object' && value !== null && value.type) {
        // It's a full field definition
        if (existing) {
          Object.assign(existing, value);
        } else {
          merged.push(Object.assign({ name }, value));
        }
      } else {
        // It's a static value
        if (existing) {
          existing._staticValue = value;
        } else {
          merged.push({ name, type: 'static', _staticValue: value });
        }
      }
    }

    return merged;
  }

  // ---------------------------------------------------------------------------
  // Field generation
  // ---------------------------------------------------------------------------

  /**
   * Generate all field values for an event.
   *
   * @param {Array} fieldDefs - Merged field definitions
   * @param {object} definition - Full definition object
   * @param {object|null} variant - Selected variant
   * @param {object} overrides - External overrides
   * @returns {object} field name -> generated value
   */
  _generateAllFields(fieldDefs, definition, variant, overrides) {
    const fields = {};

    // Resolve overrides through correlation context if available
    let resolvedOverrides = overrides;
    if (this.correlationContext && overrides) {
      resolvedOverrides = this.correlationContext.resolveOverrides(overrides);
    }

    for (const fDef of fieldDefs) {
      const name = fDef.name;

      // Priority 1: External override
      if (resolvedOverrides[name] !== undefined) {
        fields[name] = resolvedOverrides[name];
        continue;
      }

      // Priority 2: Static value from variant
      if (fDef._staticValue !== undefined) {
        fields[name] = fDef._staticValue;
        continue;
      }

      // Priority 3: Generate based on field type
      fields[name] = this._generateField(fDef, fields);
    }

    return fields;
  }

  /**
   * Generate a single field value based on its type and config.
   *
   * @param {object} fieldDef - { name, type, config }
   * @param {object} context - Already-generated fields (for dependencies)
   * @returns {*} The generated value
   */
  _generateField(fieldDef, context) {
    const config = fieldDef.config || {};
    const seed = this._getSeed();

    switch (fieldDef.type) {
      case 'static':
        return fieldDef._staticValue !== undefined ? fieldDef._staticValue : '';

      case 'ip':
        return this._generateIP(config, seed);

      case 'port':
        return this._generatePort(config, seed);

      case 'enum':
        return this._generateEnum(config, seed);

      case 'int':
        return this._generateInt(config, seed);

      case 'float':
        return this._generateFloat(config, seed);

      case 'string':
        return this._generateString(config, seed);

      case 'timestamp':
        return this._generateTimestamp(config, seed);

      case 'uuid':
        return randomizers.randomUUID(seed);

      case 'hash':
        return this._generateHash(config, seed);

      case 'hostname':
        return this._generateHostname(config, seed);

      case 'username':
        return this._generateUsername(config, seed);

      case 'email':
        return this._generateEmail(config, seed);

      case 'url':
        return this._generateURL(config, seed);

      case 'path':
        return this._generatePath(config, seed);

      case 'useragent':
        return randomizers.randomUserAgent(seed);

      // Algorithmic types — infinite uniqueness, zero pool bloat
      case 'serial':
        return randomizers.proceduralSerial(config.prefix, config.digits, seed);

      case 'counter':
        return (config.prefix || '') + String(config.base ? config.base + this._eventCounter : this._eventCounter);

      case 'procedural_hostname':
        return randomizers.proceduralHostname(seed);

      case 'procedural_name':
        return randomizers.proceduralName(seed);

      default:
        // Unknown type: return empty string or pool pick if available
        if (config.pool && config.pool.length > 0) {
          return randomizers.pickRandom(config.pool, seed);
        }
        return '';
    }
  }

  // ---------------------------------------------------------------------------
  // Type-specific generators
  // ---------------------------------------------------------------------------

  _generateIP(config, seed) {
    // Weighted IP generation with internal/external CIDRs
    if (config.internal || config.external) {
      return randomizers.randomIPv4Weighted(config, seed);
    }
    // CIDR-specific
    if (config.cidr) {
      return randomizers.randomIPv4(config.cidr, seed);
    }
    return randomizers.randomIPv4(undefined, seed);
  }

  _generatePort(config, seed) {
    // Common ports with weights
    if (config.common && config.weights) {
      return randomizers.weightedChoice(config.common, config.weights, seed);
    }
    // Port type (well-known, registered, ephemeral)
    return randomizers.randomPort(config.type, seed);
  }

  _generateEnum(config, seed) {
    if (!config.values || config.values.length === 0) return '';
    const weights = config.weights || config.values.map(() => 1);
    return randomizers.weightedChoice(config.values, weights, seed);
  }

  _generateInt(config, seed) {
    const min = config.min !== undefined ? config.min : 0;
    const max = config.max !== undefined ? config.max : 65535;
    if (seed !== undefined) {
      // Use seeded RNG for deterministic output
      const s = this._seededInt(seed, min, max);
      return s;
    }
    return min + crypto.randomInt(max - min + 1);
  }

  _generateFloat(config, seed) {
    const min = config.min !== undefined ? config.min : 0;
    const max = config.max !== undefined ? config.max : 1;
    if (seed !== undefined) {
      // Seeded float
      const normalized = ((seed * 1664525 + 1013904223) & 0x7fffffff) / 0x7fffffff;
      return min + normalized * (max - min);
    }
    return min + Math.random() * (max - min);
  }

  _generateString(config, seed) {
    // Pool of values
    if (config.pool && config.pool.length > 0) {
      return randomizers.pickRandom(config.pool, seed);
    }
    // Pattern-based generation
    if (config.pattern) {
      return this._fillPattern(config.pattern, seed);
    }
    return '';
  }

  _generateTimestamp(config, seed) {
    const format = config.format || 'iso';
    const jitterMs = config.jitterMs || 0;

    const now = new Date();

    if (jitterMs > 0) {
      let offset;
      if (seed !== undefined) {
        // Deterministic jitter from seed
        offset = this._seededInt(seed, -jitterMs, jitterMs);
      } else {
        offset = crypto.randomInt(jitterMs * 2 + 1) - jitterMs;
      }
      now.setTime(now.getTime() + offset);
    }

    // Handle PAN-OS format: YYYY/MM/DD HH:mm:ss
    if (format === 'YYYY/MM/DD HH:mm:ss' || format === 'custom_pan') {
      return this._formatPANTimestamp(now);
    }

    return randomizers.formatTimestamp(now, format);
  }

  _generateHash(config, seed) {
    switch (config.algorithm) {
      case 'sha256':
        return randomizers.randomSHA256(seed);
      case 'md5':
        return randomizers.randomMD5(seed);
      case 'random_hex':
        return this._randomHex(config.length || 32, seed);
      default:
        return randomizers.randomSHA256(seed);
    }
  }

  _generateHostname(config, seed) {
    if (config.pool && config.pool.length > 0) {
      return randomizers.pickRandom(config.pool, seed);
    }
    return randomizers.randomHostname(config.pattern || 'role-location-number', seed);
  }

  _generateUsername(config, seed) {
    // Check for pool first (e.g. syslog usr field)
    if (config.pool && config.pool.length > 0) {
      return randomizers.pickRandom(config.pool, seed);
    }

    let pattern = config.pattern || 'first.last';
    let username;

    // Map definition patterns to randomizer patterns
    if (pattern === '{first}.{last}' || pattern === 'first.last') {
      username = randomizers.randomUsername('first.last', seed);
    } else if (pattern === '{First} {Last}') {
      // Full name with capitals (for display names like Okta "an" field)
      const first = randomizers.pickRandom(randomizers.FIRST_NAMES, seed);
      const last = randomizers.pickRandom(randomizers.LAST_NAMES, seed !== undefined ? seed + 1 : undefined);
      username = `${first} ${last}`;
    } else if (pattern === '{firstinitial}.{last}' || pattern === 'firstinitial.last') {
      username = randomizers.randomUsername('firstinitial.last', seed);
    } else {
      username = randomizers.randomUsername('first.last', seed);
    }

    // Prepend domain if configured (e.g. "corp\\")
    if (config.domain) {
      username = config.domain + username;
    }

    return username;
  }

  _generateEmail(config, seed) {
    // Support both "domain" (singular) and "domains" (array) config keys
    let domain = null;
    if (config.domain) {
      domain = config.domain;
    } else if (config.domains && config.domains.length > 0) {
      domain = randomizers.pickRandom(config.domains, seed);
    }
    return randomizers.randomEmail(domain, seed);
  }

  _generateURL(config, seed) {
    const protocol = config.protocol || 'https';
    const domain = config.domain || randomizers.randomDomain(seed);
    const paths = config.paths || ['/api/v1/data', '/login', '/dashboard', '/health', '/users', '/api/v1/auth/token', '/api/v1/events', '/api/v2/search', '/api/v1/config', '/api/v1/alerts', '/api/v1/users/me', '/api/v1/webhooks', '/api/v1/ingest', '/metrics', '/status', '/favicon.ico', '/robots.txt', '/graphql', '/api/v1/reports', '/api/v1/integrations', '/api/v2/query', '/logout', '/oauth/token', '/api/v1/audit', '/api/v1/settings', '/api/v1/notifications', '/.well-known/openid-configuration', '/api/v1/assets', '/api/v1/groups', '/api/v1/roles'];
    const urlPath = randomizers.pickRandom(paths, seed !== undefined ? seed + 5 : undefined);
    return `${protocol}://${domain}${urlPath}`;
  }

  _generatePath(config, seed) {
    if (config.pool && config.pool.length > 0) {
      return randomizers.pickRandom(config.pool, seed);
    }
    // Generate a realistic-looking path
    const basePaths = [
      'C:\\Windows\\System32\\cmd.exe',
      'C:\\Windows\\System32\\powershell.exe',
      'C:\\Windows\\System32\\svchost.exe',
      'C:\\Windows\\System32\\lsass.exe',
      'C:\\Windows\\System32\\csrss.exe',
      'C:\\Windows\\System32\\conhost.exe',
      'C:\\Windows\\System32\\rundll32.exe',
      'C:\\Windows\\System32\\regsvr32.exe',
      'C:\\Windows\\System32\\msiexec.exe',
      'C:\\Windows\\System32\\certutil.exe',
      'C:\\Windows\\System32\\wscript.exe',
      'C:\\Windows\\System32\\cscript.exe',
      'C:\\Windows\\System32\\net.exe',
      'C:\\Windows\\System32\\reg.exe',
      'C:\\Windows\\System32\\mshta.exe',
      'C:\\Windows\\System32\\bitsadmin.exe',
      'C:\\Windows\\explorer.exe',
      'C:\\Windows\\System32\\wbem\\wmiprvse.exe',
      'C:\\Windows\\System32\\dllhost.exe',
      'C:\\Windows\\System32\\mmc.exe',
      'C:\\Program Files\\Windows Defender\\MsMpEng.exe',
      'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
      'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      '/usr/bin/bash',
      '/usr/bin/sh',
      '/usr/bin/python3',
      '/usr/local/bin/node',
      '/usr/bin/perl',
      '/usr/bin/ruby',
      '/usr/sbin/sshd',
      '/usr/sbin/nginx',
      '/usr/sbin/apache2',
      '/usr/bin/curl',
      '/usr/bin/wget',
      '/usr/bin/git',
      '/usr/bin/docker',
      '/usr/bin/kubectl',
      '/usr/local/bin/terraform',
      '/usr/bin/find',
      '/usr/bin/grep',
      '/usr/bin/awk',
      '/var/log/syslog',
      '/var/log/auth.log',
      '/etc/passwd',
      '/opt/app/bin/service',
    ];
    return randomizers.pickRandom(basePaths, seed);
  }

  // ---------------------------------------------------------------------------
  // Pattern filling
  // ---------------------------------------------------------------------------

  /**
   * Fill a pattern string with random data.
   * Supports:
   *   - {random:N}       -> N random alphanumeric characters
   *   - {random_hex:N}   -> N random hex characters
   *   - {first}          -> random first name (lowercase)
   *   - {last}           -> random last name (lowercase)
   *   - {First}          -> random first name (capitalized)
   *   - {Last}           -> random last name (capitalized)
   *
   * @param {string} pattern
   * @param {number} [seed]
   * @returns {string}
   */
  _fillPattern(pattern, seed) {
    let result = pattern;
    let offset = 0;

    // {random_hex:N} -> N random hex chars (must come before {random:N})
    result = result.replace(/\{random_hex:(\d+)\}/g, (match, len) => {
      return this._randomHex(parseInt(len, 10), seed !== undefined ? seed + (offset++) : undefined);
    });

    // {random:N} -> N random alphanumeric chars (used for SIDs, Okta IDs, etc.)
    result = result.replace(/\{random:(\d+)\}/g, (match, len) => {
      return this._randomAlphaNum(parseInt(len, 10), seed !== undefined ? seed + (offset++) : undefined);
    });

    // {first} / {First} / {last} / {Last}
    result = result.replace(/\{first\}/gi, (match) => {
      const name = randomizers.pickRandom(randomizers.FIRST_NAMES, seed !== undefined ? seed + (offset++) : undefined);
      return match === '{First}' ? name : name.toLowerCase();
    });

    result = result.replace(/\{last\}/gi, (match) => {
      const name = randomizers.pickRandom(randomizers.LAST_NAMES, seed !== undefined ? seed + (offset++) : undefined);
      return match === '{Last}' ? name : name.toLowerCase();
    });

    return result;
  }

  // ---------------------------------------------------------------------------
  // Calculated fields
  // ---------------------------------------------------------------------------

  /**
   * Apply calculated fields (e.g., syslog priority = facility * 8 + severity).
   */
  _applyCalculatedFields(fields, definition) {
    // Syslog priority calculation
    if (definition.priorityCalc && definition.priorityCalc === 'fac * 8 + sev') {
      const fac = typeof fields.fac === 'number' ? fields.fac : parseInt(fields.fac, 10) || 0;
      const sev = typeof fields.sev === 'number' ? fields.sev : parseInt(fields.sev, 10) || 0;
      fields.pri = fac * 8 + sev;
    }
  }

  // ---------------------------------------------------------------------------
  // Event rendering (format-specific)
  // ---------------------------------------------------------------------------

  /**
   * Render the final raw event string based on the definition format.
   */
  _renderEvent(definition, variant, variantKey, fields) {
    const format = definition.format;

    switch (format) {
      case 'csv':
        return this._renderCSV(definition, fields);

      case 'xml':
        return this._renderXML(definition, variant, fields);

      case 'syslog_rfc5424':
        return this._renderSyslog(definition, variant, fields);

      case 'json':
        return this._renderJSON(definition, variant, fields);

      default:
        // Fallback: simple template rendering
        return this._renderTemplate(definition.template || '', fields);
    }
  }

  /**
   * CSV format (Palo Alto traffic).
   * Uses the template string with {{field}} placeholders.
   */
  _renderCSV(definition, fields) {
    return this._renderTemplate(definition.template, fields);
  }

  /**
   * XML format (Windows Security Event Log).
   * Builds: xmlHeader + <EventData> with variant-specific data pairs + xmlFooter
   */
  _renderXML(definition, variant, fields) {
    // Render the header (contains System block)
    let xml = this._renderTemplate(definition.xmlHeader, fields);

    // Build EventData section from variant
    if (variant && variant.eventData) {
      xml += '<EventData>';
      for (const [dataName, dataTemplate] of variant.eventData) {
        const value = this._renderTemplate(dataTemplate, fields);
        xml += `<Data Name='${dataName}'>${value}</Data>`;
      }
      xml += '</EventData>';
    }

    xml += definition.xmlFooter;
    return xml;
  }

  /**
   * Syslog RFC 5424 format.
   * Each variant has its own template with {{pri}} calculated from facility and severity.
   */
  _renderSyslog(definition, variant, fields) {
    if (variant && variant.template) {
      // Variant-specific template (most syslog variants have their own)
      return this._renderTemplate(variant.template, fields);
    }
    // Fallback to base template
    return this._renderTemplate(definition.template, fields);
  }

  /**
   * JSON format - handles two sub-patterns:
   *
   * 1. CrowdStrike pattern: templatePrefix + bodyTemplate + templateSuffix
   *    The prefix/suffix are in the definition, bodyTemplate in the variant.
   *
   * 2. Okta pattern: jsonBase merged with variant jsonMerge
   *    Both are objects; jsonMerge is deep-merged into jsonBase,
   *    then all {{field}} references are resolved.
   */
  _renderJSON(definition, variant, fields) {
    // Okta-style: jsonBase + jsonMerge
    if (definition.jsonBase && variant && variant.jsonMerge) {
      return this._renderJSONMerge(definition, variant, fields);
    }

    // CrowdStrike-style: prefix + body + suffix
    // These templates produce raw JSON strings, so field values containing
    // special chars (backslashes in Windows paths, quotes, etc.) must be
    // JSON-escaped before insertion.
    if (definition.templatePrefix && variant && variant.bodyTemplate) {
      const prefix = this._renderTemplateJSON(definition.templatePrefix, fields);
      const body = this._renderTemplateJSON(variant.bodyTemplate, fields);
      const suffix = this._renderTemplateJSON(definition.templateSuffix || '', fields);
      return prefix + body + suffix;
    }

    // Fallback: render the template directly
    if (definition.template && definition.template !== 'json_merge') {
      return this._renderTemplate(definition.template, fields);
    }

    // Last resort: serialize fields as JSON
    return JSON.stringify(fields);
  }

  /**
   * Render the Okta-style JSON merge pattern.
   * Deep-merges jsonBase with variant's jsonMerge, then resolves
   * all {{field}} template references in string values.
   */
  _renderJSONMerge(definition, variant, fields) {
    const base = this._deepClone(definition.jsonBase);
    const merged = this._deepMerge(base, variant.jsonMerge);
    const resolved = this._resolveJSONTemplates(merged, fields);
    return JSON.stringify(resolved);
  }

  // ---------------------------------------------------------------------------
  // Template rendering
  // ---------------------------------------------------------------------------

  /**
   * Replace all {{field_name}} placeholders in a template string.
   * Supports:
   *   - {{field_name}} -> direct field value
   *   - {{actor.alternateId}} -> nested field path (dot notation)
   *   - {{PRIORITY}} -> calculated fields
   *
   * @param {string} template
   * @param {object} fields
   * @returns {string}
   */
  _renderTemplate(template, fields) {
    if (!template) return '';

    return template.replace(/\{\{(\w[\w.]*)\}\}/g, (match, key) => {
      // Direct field lookup
      if (fields[key] !== undefined) {
        return String(fields[key]);
      }

      // Nested field lookup (e.g. "actor.alternateId")
      const parts = key.split('.');
      let value = fields;
      for (const part of parts) {
        if (value && typeof value === 'object' && part in value) {
          value = value[part];
        } else {
          value = undefined;
          break;
        }
      }
      if (value !== undefined) {
        return String(value);
      }

      // Not found: return the placeholder as-is (not an error)
      return match;
    });
  }

  /**
   * Render a template where the output is embedded in a JSON string context.
   * String values are JSON-escaped (backslashes, quotes, control chars) before
   * substitution so the resulting concatenated string is valid JSON.
   *
   * Numeric values that appear in a numeric position (no surrounding quotes)
   * are inserted as-is.
   *
   * @param {string} template
   * @param {object} fields
   * @returns {string}
   */
  _renderTemplateJSON(template, fields) {
    if (!template) return '';

    return template.replace(/\{\{(\w[\w.]*)\}\}/g, (match, key) => {
      let value;
      // Direct field lookup
      if (fields[key] !== undefined) {
        value = fields[key];
      } else {
        // Nested field lookup
        const parts = key.split('.');
        value = fields;
        for (const part of parts) {
          if (value && typeof value === 'object' && part in value) {
            value = value[part];
          } else {
            value = undefined;
            break;
          }
        }
      }

      if (value === undefined) return match;

      // Numbers and booleans can be inserted directly
      if (typeof value === 'number' || typeof value === 'boolean') {
        return String(value);
      }

      // Strings need JSON-escaping for backslashes, quotes, control chars
      return this._jsonEscapeString(String(value));
    });
  }

  /**
   * Escape a string for safe embedding inside a JSON string (between quotes).
   * Handles backslashes, double-quotes, and control characters.
   */
  _jsonEscapeString(str) {
    return str
      .replace(/\\/g, '\\\\')
      .replace(/"/g, '\\"')
      .replace(/\n/g, '\\n')
      .replace(/\r/g, '\\r')
      .replace(/\t/g, '\\t');
  }

  /**
   * Walk a JSON object and resolve all {{field}} template strings.
   */
  _resolveJSONTemplates(obj, fields) {
    if (typeof obj === 'string') {
      // If the entire string is a single {{field}} placeholder that maps to a non-string,
      // return the raw value (preserves numbers, booleans, etc.)
      const singleMatch = obj.match(/^\{\{(\w[\w.]*)\}\}$/);
      if (singleMatch) {
        const key = singleMatch[1];
        if (fields[key] !== undefined) {
          return fields[key];
        }
      }
      return this._renderTemplate(obj, fields);
    }

    if (Array.isArray(obj)) {
      return obj.map(item => this._resolveJSONTemplates(item, fields));
    }

    if (obj !== null && typeof obj === 'object') {
      const result = {};
      for (const [key, value] of Object.entries(obj)) {
        result[key] = this._resolveJSONTemplates(value, fields);
      }
      return result;
    }

    return obj;
  }

  // ---------------------------------------------------------------------------
  // Utility methods
  // ---------------------------------------------------------------------------

  _getSeed() {
    if (this.seed !== undefined) {
      return this.seed + this._eventCounter;
    }
    return undefined;
  }

  /**
   * Seeded integer in range [min, max] (inclusive).
   */
  _seededInt(seed, min, max) {
    const s = ((seed * 1664525 + 1013904223) & 0x7fffffff);
    return min + (s % (max - min + 1));
  }

  _formatPANTimestamp(date) {
    const y = date.getFullYear();
    const mo = String(date.getMonth() + 1).padStart(2, '0');
    const d = String(date.getDate()).padStart(2, '0');
    const h = String(date.getHours()).padStart(2, '0');
    const mi = String(date.getMinutes()).padStart(2, '0');
    const s = String(date.getSeconds()).padStart(2, '0');
    return `${y}/${mo}/${d} ${h}:${mi}:${s}`;
  }

  _randomHex(length, seed) {
    const chars = '0123456789abcdef';
    const result = [];
    for (let i = 0; i < length; i++) {
      const idx = seed !== undefined
        ? Math.abs((seed + i) * 1664525 + 1013904223) % 16
        : crypto.randomInt(16);
      result.push(chars[idx]);
    }
    return result.join('');
  }

  _randomAlphaNum(length, seed) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const result = [];
    for (let i = 0; i < length; i++) {
      const idx = seed !== undefined
        ? Math.abs((seed + i) * 1664525 + 1013904223) % chars.length
        : crypto.randomInt(chars.length);
      result.push(chars[idx]);
    }
    return result.join('');
  }

  _randomDigits(length, seed) {
    const result = [];
    for (let i = 0; i < length; i++) {
      const digit = seed !== undefined
        ? Math.abs((seed + i) * 1664525 + 1013904223) % 10
        : crypto.randomInt(10);
      result.push(String(digit));
    }
    return result.join('');
  }

  _deepClone(obj) {
    if (obj === null || typeof obj !== 'object') return obj;
    if (Array.isArray(obj)) return obj.map(item => this._deepClone(item));
    const result = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = this._deepClone(value);
    }
    return result;
  }

  _deepMerge(target, source) {
    if (source === null || typeof source !== 'object') return source;
    if (Array.isArray(source)) return this._deepClone(source);

    const result = this._deepClone(target && typeof target === 'object' ? target : {});
    for (const [key, value] of Object.entries(source)) {
      if (value !== null && typeof value === 'object' && !Array.isArray(value)
          && result[key] && typeof result[key] === 'object' && !Array.isArray(result[key])) {
        result[key] = this._deepMerge(result[key], value);
      } else {
        result[key] = this._deepClone(value);
      }
    }
    return result;
  }
}

module.exports = { DataTapGenerator };
