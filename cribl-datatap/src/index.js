'use strict';

/**
 * DataTap — Main Library Entry Point
 *
 * Public API for generating production-realistic streaming data.
 * Wraps the engine components (generator, correlator, scheduler)
 * behind a clean, ergonomic interface.
 *
 * @example
 *   const DataTap = require('cribl-datatap');
 *
 *   // Generate a single event
 *   const tap = new DataTap();
 *   const event = tap.generate('pan:traffic');
 *
 *   // Stream events to a callback
 *   const tap = new DataTap({ eps: 50, onEvent: (e) => process.stdout.write(e.raw + '\n') });
 *   tap.stream(['pan:traffic', 'syslog']);
 */

const { DataTapGenerator } = require('./engine/generator');
const { CorrelationContext } = require('./engine/correlator');
const { EventScheduler } = require('./engine/scheduler');
const definitions = require('./definitions');
const scenarios = require('./scenarios');

class DataTap {
  /**
   * @param {Object} options
   * @param {number}   [options.eps=10]       - Default events per second
   * @param {Function} [options.onEvent]      - Callback for each generated event
   * @param {boolean}  [options.correlate]    - Enable correlation context
   */
  constructor(options = {}) {
    this.options = options;
    this.generator = new DataTapGenerator(options);
    this.scheduler = null;
    this.correlation = options.correlate ? new CorrelationContext() : null;
    this._running = false;
    this._onEvent = options.onEvent || null;
    this._eps = options.eps || 10;
  }

  /**
   * Generate a single event for the given sourcetype.
   *
   * @param {string} sourcetype - e.g. 'pan:traffic', 'syslog', 'okta:system'
   * @param {Object} [overrides={}] - Field overrides to inject into the event
   * @returns {Object} Generated event object with { sourcetype, timestamp, fields, raw }
   */
  generate(sourcetype, overrides = {}) {
    return this.generator.generate(sourcetype, overrides);
  }

  /**
   * Start streaming events for one or more sourcetypes.
   *
   * @param {string|string[]} sourcetypes - Sourcetype(s) to generate
   * @param {Object} [options={}]
   * @param {number}   [options.eps]       - Events per second (overrides constructor)
   * @param {number}   [options.duration]  - Duration in seconds (0 = infinite)
   * @param {Function} [options.onEvent]   - Per-event callback (overrides constructor)
   * @param {string}   [options.format]    - Output format: 'raw', 'json', 'ndjson'
   */
  stream(sourcetypes, options = {}) {
    const types = Array.isArray(sourcetypes) ? sourcetypes : [sourcetypes];
    const eps = options.eps || this._eps;
    const duration = options.duration || 0;
    const onEvent = options.onEvent || this._onEvent;
    const format = options.format || 'raw';

    if (types.length === 0) {
      throw new Error('At least one sourcetype is required');
    }

    let eventIndex = 0;

    // generatorFn: called by the scheduler to produce each event
    const generatorFn = () => {
      const sourcetype = types[eventIndex % types.length];
      eventIndex++;
      return this.generator.generate(sourcetype);
    };

    // onEvent: called after each event is generated
    const eventCallback = onEvent ? (event) => onEvent(event, format) : null;

    this.scheduler = new EventScheduler({
      eps,
      onEvent: eventCallback,
    });

    this._running = true;
    this.scheduler.start(generatorFn);

    // Stop after duration if specified
    if (duration > 0) {
      this._durationTimer = setTimeout(() => {
        this.stop();
      }, duration * 1000);
    }
  }

  /**
   * Run a predefined scenario with correlated events.
   *
   * @param {string} scenarioName - e.g. 'brute-force', 'data-exfil'
   * @param {Object} [options={}]
   * @param {number}   [options.eps]           - Base events per second
   * @param {number}   [options.timeScale]     - Speed multiplier (10 = 10x faster)
   * @param {Function} [options.onEvent]       - Per-event callback
   * @param {Function} [options.onPhaseChange] - Called when scenario phase changes
   * @param {string}   [options.format]        - Output format
   */
  runScenario(scenarioName, options = {}) {
    const scenario = scenarios.getScenario(scenarioName);
    const eps = options.eps || this._eps;
    const timeScale = options.timeScale || 1;
    const onEvent = options.onEvent || this._onEvent;
    const onPhaseChange = options.onPhaseChange || null;
    const format = options.format || 'raw';

    // Initialize correlation context with scenario actors
    const correlation = new CorrelationContext();
    if (scenario.actors) {
      const normalizedActors = this._normalizeActorDefs(scenario.actors);
      correlation.initActors(normalizedActors);
    }

    this._running = true;

    const runPhase = (phaseIndex) => {
      if (phaseIndex >= scenario.phases.length || !this._running) {
        this.stop();
        if (options.onComplete) options.onComplete();
        return;
      }

      const phase = scenario.phases[phaseIndex];

      if (onPhaseChange) {
        onPhaseChange(phase, phaseIndex, scenario.phases.length);
      }

      // Compute phase duration from { min, max } range, adjusted by timeScale
      let phaseDurationMs;
      if (phase.duration && typeof phase.duration === 'object') {
        const min = phase.duration.min || 60000;
        const max = phase.duration.max || min;
        phaseDurationMs = (min + Math.random() * (max - min)) / timeScale;
      } else {
        phaseDurationMs = (phase.duration || 60000) / timeScale;
      }

      // Phase events define what to generate with weights
      const phaseEvents = phase.events || [];
      if (phaseEvents.length === 0) {
        // Empty phase — skip to next
        this._phaseTimer = setTimeout(() => runPhase(phaseIndex + 1), phaseDurationMs);
        return;
      }

      // Calculate average rateMultiplier for overall phase EPS
      const avgRate = phaseEvents.reduce((s, e) => s + (e.rateMultiplier || 1), 0) / phaseEvents.length;
      const phaseEps = Math.max(1, Math.round(eps * avgRate));

      // Build weights array for event selection
      const weights = phaseEvents.map(e => e.weight || 1);
      const totalWeight = weights.reduce((s, w) => s + w, 0);
      const normalizedWeights = weights.map(w => w / totalWeight);

      const generatorFn = () => {
        // Weighted random selection of event template
        const r = Math.random();
        let cumulative = 0;
        let selectedEvent = phaseEvents[0];
        for (let i = 0; i < phaseEvents.length; i++) {
          cumulative += normalizedWeights[i];
          if (r <= cumulative) {
            selectedEvent = phaseEvents[i];
            break;
          }
        }

        const sourcetype = selectedEvent.sourcetype;
        if (!sourcetype) return null;

        // Resolve actor references in overrides
        const rawOverrides = selectedEvent.overrides || {};
        const resolvedOverrides = correlation.resolveOverrides(rawOverrides);

        try {
          const event = this.generator.generate(sourcetype, resolvedOverrides);
          correlation.trackEvent(event);
          return event;
        } catch (e) {
          return null;
        }
      };

      const eventCallback = onEvent ? (event) => onEvent(event, format) : null;

      this.scheduler = new EventScheduler({
        eps: phaseEps,
        onEvent: eventCallback,
      });

      this.scheduler.start(generatorFn);

      // Move to next phase after duration
      this._phaseTimer = setTimeout(() => {
        if (this.scheduler) {
          this.scheduler.stop();
        }
        runPhase(phaseIndex + 1);
      }, phaseDurationMs);
    };

    runPhase(0);
  }

  /**
   * Normalize scenario actor definitions to the format expected by CorrelationContext.
   * Scenarios use shorthand like { ip: { cidr: '...' } } but the correlator
   * expects { ip: { type: 'ip', config: { cidr: '...' } } }.
   */
  _normalizeActorDefs(actorDefs) {
    const normalized = {};
    for (const [name, fields] of Object.entries(actorDefs)) {
      normalized[name] = {};
      for (const [key, val] of Object.entries(fields)) {
        if (key === 'type' || key === 'count' || key === 'os' || key === 'department') {
          // Metadata fields — pass through as string values
          normalized[name][key] = typeof val === 'string' ? val : val;
          continue;
        }
        if (typeof val === 'string' || typeof val === 'number' || typeof val === 'boolean') {
          normalized[name][key] = val;
          continue;
        }
        if (val && typeof val === 'object') {
          // Detect field type from keys present
          if (val.cidr) {
            normalized[name][key] = { type: 'ip', config: { cidr: val.cidr } };
          } else if (val.pattern) {
            // Could be username or hostname
            const isHostname = key === 'hostname' || val.pattern.includes('location') || val.pattern.includes('role');
            normalized[name][key] = { type: isHostname ? 'hostname' : 'username', config: { pattern: val.pattern } };
          } else if (val.pool) {
            normalized[name][key] = { type: 'string', config: { pool: val.pool } };
          } else if (val.min !== undefined && val.max !== undefined) {
            normalized[name][key] = { type: 'int', config: val };
          } else {
            normalized[name][key] = val;
          }
        }
      }
    }
    return normalized;
  }

  /**
   * Stop all streaming and clean up timers.
   */
  stop() {
    this._running = false;

    if (this.scheduler) {
      this.scheduler.stop();
      this.scheduler = null;
    }

    if (this._durationTimer) {
      clearTimeout(this._durationTimer);
      this._durationTimer = null;
    }

    if (this._phaseTimer) {
      clearTimeout(this._phaseTimer);
      this._phaseTimer = null;
    }
  }

  /**
   * Check if the generator is currently running.
   * @returns {boolean}
   */
  get running() {
    return this._running;
  }

  /**
   * List all available sourcetype definitions.
   * @returns {string[]}
   */
  static listSourcetypes() {
    return definitions.listDefinitions();
  }

  /**
   * List all available scenarios with metadata.
   * @returns {Array<{name: string, description: string, phaseCount: number}>}
   */
  static listScenarios() {
    return scenarios.listScenarios();
  }

  /**
   * Get detailed info about a sourcetype definition.
   * @param {string} sourcetype
   * @returns {Object}
   */
  static getSourcetypeInfo(sourcetype) {
    return definitions.loadDefinition(sourcetype);
  }

  /**
   * Get a scenario definition by name.
   * @param {string} name
   * @returns {Object}
   */
  static getScenario(name) {
    return scenarios.getScenario(name);
  }
}

module.exports = DataTap;
