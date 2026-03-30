'use strict';

const randomizers = require('./randomizers');

/**
 * Correlation engine that maintains shared state across sourcetypes.
 *
 * When a scenario defines actors (attacker, victim, server, etc.),
 * the CorrelationContext resolves those into concrete values and
 * ensures the same IP, username, hostname, etc. appear consistently
 * across events from different sourcetypes.
 */
class CorrelationContext {
  constructor() {
    /** @type {Object<string, object>} Named actors with resolved concrete values */
    this.actors = {};

    /** @type {Map<string, object>} Active sessions keyed by session ID */
    this.sessions = new Map();

    /** @type {Array<object>} Ordered event timeline for post-hoc correlation */
    this.timeline = [];

    /** @type {number} Monotonically increasing counter for ordering */
    this._sequenceNumber = 0;
  }

  // ---------------------------------------------------------------------------
  // Actor management
  // ---------------------------------------------------------------------------

  /**
   * Initialize actors for a scenario.
   *
   * Accepts a map of actor names to field specifications, resolves each
   * field into a concrete value, and stores them for later reference.
   *
   * Example actorDefs:
   * {
   *   attacker: {
   *     ip: { type: "ip", config: { cidr: "203.0.113.0/24" } },
   *     geo: { type: "geo", config: {} }
   *   },
   *   victim: {
   *     username: { type: "username", config: { pattern: "first.last" } },
   *     email: { type: "email", config: { domain: "acme.com" } },
   *     hostname: { type: "hostname", config: { pool: ["WKS-NYC-0142"] } }
   *   }
   * }
   *
   * @param {object} actorDefs - Map of actor name -> field definitions
   */
  initActors(actorDefs) {
    for (const [actorName, fields] of Object.entries(actorDefs)) {
      this.actors[actorName] = this._resolveActorFields(actorName, fields);
    }
  }

  /**
   * Get the resolved values for a named actor.
   * @param {string} actorName
   * @returns {object|null}
   */
  getActor(actorName) {
    return this.actors[actorName] || null;
  }

  /**
   * Get all resolved actors.
   * @returns {object}
   */
  getActors() {
    return Object.assign({}, this.actors);
  }

  /**
   * Update a specific field on a named actor.
   * Useful for mid-scenario changes (e.g., lateral movement to a new host).
   *
   * @param {string} actorName
   * @param {string} fieldName
   * @param {*} value
   */
  updateActor(actorName, fieldName, value) {
    if (!this.actors[actorName]) {
      this.actors[actorName] = {};
    }
    this.actors[actorName][fieldName] = value;
  }

  // ---------------------------------------------------------------------------
  // Override resolution
  // ---------------------------------------------------------------------------

  /**
   * Resolve template references in an overrides object.
   *
   * Deep-walks the overrides and replaces any string matching the pattern
   * {{actorName.fieldName}} with the concrete value from resolved actors.
   *
   * Example:
   *   resolveOverrides({ src: "{{attacker.ip}}", srcuser: "{{victim.username}}" })
   *   -> { src: "203.0.113.47", srcuser: "john.smith" }
   *
   * @param {object} overrides
   * @returns {object} New object with all actor references resolved
   */
  resolveOverrides(overrides) {
    if (!overrides || typeof overrides !== 'object') return overrides;
    return this._deepResolve(overrides);
  }

  // ---------------------------------------------------------------------------
  // Session tracking
  // ---------------------------------------------------------------------------

  /**
   * Start a new session.
   * @param {string} sessionId - Unique session identifier
   * @param {object} metadata - Arbitrary session metadata
   * @returns {object} The session object
   */
  startSession(sessionId, metadata = {}) {
    const session = {
      id: sessionId,
      startTime: new Date().toISOString(),
      endTime: null,
      metadata,
      events: [],
      active: true,
    };
    this.sessions.set(sessionId, session);
    return session;
  }

  /**
   * End an active session.
   * @param {string} sessionId
   */
  endSession(sessionId) {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.endTime = new Date().toISOString();
      session.active = false;
    }
  }

  /**
   * Get a session by ID.
   * @param {string} sessionId
   * @returns {object|undefined}
   */
  getSession(sessionId) {
    return this.sessions.get(sessionId);
  }

  /**
   * List active sessions.
   * @returns {Array<object>}
   */
  getActiveSessions() {
    const active = [];
    for (const session of this.sessions.values()) {
      if (session.active) active.push(session);
    }
    return active;
  }

  // ---------------------------------------------------------------------------
  // Event tracking
  // ---------------------------------------------------------------------------

  /**
   * Track an event in the timeline and optionally associate with a session.
   *
   * @param {object} event - { raw, fields, sourcetype, timestamp }
   * @param {string} [sessionId] - Optional session to associate with
   */
  trackEvent(event, sessionId) {
    this._sequenceNumber++;

    const tracked = {
      seq: this._sequenceNumber,
      sourcetype: event.sourcetype,
      timestamp: event.timestamp,
      fields: event.fields,
      sessionId: sessionId || null,
    };

    this.timeline.push(tracked);

    // Associate with session if provided
    if (sessionId) {
      const session = this.sessions.get(sessionId);
      if (session && session.active) {
        session.events.push(tracked);
      }
    }
  }

  /**
   * Get events from the timeline, optionally filtered.
   *
   * @param {object} [filter]
   * @param {string} [filter.sourcetype] - Filter by sourcetype
   * @param {number} [filter.last] - Return only the last N events
   * @returns {Array<object>}
   */
  getTimeline(filter) {
    let events = this.timeline;

    if (filter) {
      if (filter.sourcetype) {
        events = events.filter(e => e.sourcetype === filter.sourcetype);
      }
      if (filter.last && filter.last > 0) {
        events = events.slice(-filter.last);
      }
    }

    return events;
  }

  // ---------------------------------------------------------------------------
  // Correlation state
  // ---------------------------------------------------------------------------

  /**
   * Get the current correlation state for use by generators.
   * Returns a snapshot of actors and session data.
   *
   * @returns {{ actors: object, activeSessions: Array, eventCount: number }}
   */
  getCorrelationState() {
    return {
      actors: this.getActors(),
      activeSessions: this.getActiveSessions(),
      eventCount: this.timeline.length,
      lastEvent: this.timeline.length > 0 ? this.timeline[this.timeline.length - 1] : null,
    };
  }

  /**
   * Reset all state. Useful between scenario runs.
   */
  reset() {
    this.actors = {};
    this.sessions.clear();
    this.timeline = [];
    this._sequenceNumber = 0;
  }

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  /**
   * Resolve actor field definitions into concrete values.
   */
  _resolveActorFields(actorName, fields) {
    const resolved = {};

    for (const [fieldName, fieldDef] of Object.entries(fields)) {
      if (typeof fieldDef === 'string' || typeof fieldDef === 'number' || typeof fieldDef === 'boolean') {
        // Already a concrete value
        resolved[fieldName] = fieldDef;
        continue;
      }

      if (!fieldDef || typeof fieldDef !== 'object') {
        resolved[fieldName] = fieldDef;
        continue;
      }

      // Resolve based on type
      resolved[fieldName] = this._resolveFieldValue(fieldDef);
    }

    // Auto-resolve geo from IP if geo was requested but IP is available
    if (resolved.ip && !resolved.geo && fields.geo) {
      resolved.geo = randomizers.randomGeoIP(resolved.ip);
    }

    return resolved;
  }

  /**
   * Resolve a single field definition into a concrete value.
   */
  _resolveFieldValue(fieldDef) {
    const config = fieldDef.config || {};

    switch (fieldDef.type) {
      case 'ip':
        if (config.internal || config.external) {
          return randomizers.randomIPv4Weighted(config);
        }
        if (config.cidr) {
          return randomizers.randomIPv4(config.cidr);
        }
        return randomizers.randomPublicIP();

      case 'username':
        if (config.pool && config.pool.length > 0) {
          return randomizers.pickRandom(config.pool);
        }
        return randomizers.randomUsername(this._mapUsernamePattern(config.pattern));

      case 'email':
        return randomizers.randomEmail(config.domain);

      case 'hostname':
        if (config.pool && config.pool.length > 0) {
          return randomizers.pickRandom(config.pool);
        }
        return randomizers.randomHostname(config.pattern || 'role-location-number');

      case 'geo':
        return randomizers.randomGeoIP();

      case 'domain':
        return randomizers.randomDomain();

      case 'uuid':
        return randomizers.randomUUID();

      case 'session_id':
        return randomizers.randomSessionID(config.length);

      case 'int': {
        const min = config.min || 0;
        const max = config.max || 65535;
        const crypto = require('crypto');
        return min + crypto.randomInt(max - min + 1);
      }

      default:
        // Try pool, then pattern, then return as-is
        if (config.pool && config.pool.length > 0) {
          return randomizers.pickRandom(config.pool);
        }
        if (config.value !== undefined) {
          return config.value;
        }
        return null;
    }
  }

  /**
   * Map definition-style username patterns to randomizer patterns.
   */
  _mapUsernamePattern(pattern) {
    if (!pattern) return 'first.last';
    if (pattern === '{first}.{last}' || pattern === 'first.last') return 'first.last';
    if (pattern === '{firstinitial}.{last}' || pattern === 'firstinitial.last') return 'firstinitial.last';
    return 'first.last';
  }

  /**
   * Deep-walk an object and resolve {{actor.field}} references.
   */
  _deepResolve(obj) {
    if (typeof obj === 'string') {
      return this._resolveString(obj);
    }

    if (Array.isArray(obj)) {
      return obj.map(item => this._deepResolve(item));
    }

    if (obj !== null && typeof obj === 'object') {
      const result = {};
      for (const [key, value] of Object.entries(obj)) {
        result[key] = this._deepResolve(value);
      }
      return result;
    }

    return obj;
  }

  /**
   * Resolve {{actor.field}} references within a single string.
   * If the entire string is a single reference, return the raw value
   * (preserving type). Otherwise do string interpolation.
   */
  _resolveString(str) {
    // Check if the entire string is a single {{actor.field}} reference
    const singleMatch = str.match(/^\{\{(\w+)\.(\w[\w.]*)\}\}$/);
    if (singleMatch) {
      const [, actorName, fieldPath] = singleMatch;
      const value = this._lookupActorField(actorName, fieldPath);
      if (value !== undefined) return value;
      return str; // Return unresolved
    }

    // String interpolation for mixed content
    return str.replace(/\{\{(\w+)\.(\w[\w.]*)\}\}/g, (match, actorName, fieldPath) => {
      const value = this._lookupActorField(actorName, fieldPath);
      if (value !== undefined) return String(value);
      return match; // Leave unresolved references as-is
    });
  }

  /**
   * Look up a field value from a named actor, supporting dot-path traversal.
   * E.g., "attacker" + "geo.city" -> actors.attacker.geo.city
   */
  _lookupActorField(actorName, fieldPath) {
    const actor = this.actors[actorName];
    if (!actor) return undefined;

    const parts = fieldPath.split('.');
    let value = actor;
    for (const part of parts) {
      if (value && typeof value === 'object' && part in value) {
        value = value[part];
      } else {
        return undefined;
      }
    }
    return value;
  }
}

module.exports = { CorrelationContext };
