'use strict';

/**
 * EPS (events per second) control and event scheduling.
 *
 * Emits events at a configurable rate, handling both low-EPS
 * (fractional, e.g. 0.5 = one event every 2 seconds) and high-EPS
 * (batched, e.g. 1000 = 100 events per 100ms tick) scenarios.
 */
class EventScheduler {
  /**
   * @param {object} options
   * @param {number} [options.eps=10]       - Target events per second
   * @param {function} [options.onEvent]    - Callback invoked for each generated event
   * @param {function} [options.onError]    - Callback invoked when generatorFn throws
   * @param {number} [options.maxBatchSize] - Maximum events per tick (default: 200)
   */
  constructor(options = {}) {
    this.eps = options.eps || 10;
    this.onEvent = options.onEvent || null;
    this.onError = options.onError || null;
    this.maxBatchSize = options.maxBatchSize || 200;

    this.running = false;
    this._timer = null;
    this._generatorFn = null;

    // Stats
    this._eventsGenerated = 0;
    this._bytesGenerated = 0;
    this._startTime = null;
    this._lastTickTime = null;
    this._fractionalAccumulator = 0;
  }

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  /**
   * Start streaming events at the configured EPS.
   *
   * @param {function} generatorFn - Called to produce events; should return
   *   an event object with at least a `raw` string property.
   *   Signature: () => { raw: string, fields: object, ... }
   */
  start(generatorFn) {
    if (this.running) return;
    if (typeof generatorFn !== 'function') {
      throw new Error('generatorFn must be a function');
    }

    this._generatorFn = generatorFn;
    this.running = true;
    this._startTime = Date.now();
    this._lastTickTime = this._startTime;
    this._fractionalAccumulator = 0;

    this._scheduleTick();
  }

  /**
   * Stop the scheduler.
   */
  stop() {
    this.running = false;
    if (this._timer !== null) {
      clearTimeout(this._timer);
      this._timer = null;
    }
    this._generatorFn = null;
  }

  /**
   * Update the EPS while running.
   * @param {number} newEps
   */
  setEPS(newEps) {
    if (typeof newEps !== 'number' || newEps <= 0) {
      throw new Error('EPS must be a positive number');
    }
    this.eps = newEps;
    // The next tick will pick up the new rate automatically
  }

  // ---------------------------------------------------------------------------
  // Stats
  // ---------------------------------------------------------------------------

  /**
   * Get runtime statistics.
   * @returns {{ eventsGenerated: number, actualEPS: number, uptime: number, bytesGenerated: number, targetEPS: number }}
   */
  getStats() {
    const now = Date.now();
    const uptimeMs = this._startTime ? now - this._startTime : 0;
    const uptimeSec = uptimeMs / 1000;

    return {
      eventsGenerated: this._eventsGenerated,
      actualEPS: uptimeSec > 0 ? Math.round((this._eventsGenerated / uptimeSec) * 100) / 100 : 0,
      targetEPS: this.eps,
      uptime: Math.round(uptimeMs),
      uptimeFormatted: this._formatUptime(uptimeMs),
      bytesGenerated: this._bytesGenerated,
      running: this.running,
    };
  }

  /**
   * Reset stats without stopping.
   */
  resetStats() {
    this._eventsGenerated = 0;
    this._bytesGenerated = 0;
    this._startTime = this.running ? Date.now() : null;
  }

  // ---------------------------------------------------------------------------
  // Internal scheduling
  // ---------------------------------------------------------------------------

  /**
   * Schedule the next tick.
   *
   * Strategy:
   *   - Low EPS (< 1):    Emit 1 event every (1/eps) seconds
   *   - Normal EPS (1-50): Emit 1 event per tick, tick interval = 1000/eps ms
   *   - High EPS (> 50):   Batch multiple events per tick at ~10ms intervals
   */
  _scheduleTick() {
    if (!this.running) return;

    const { intervalMs, eventsPerTick } = this._computeTickParams();

    this._timer = setTimeout(() => {
      this._executeTick(eventsPerTick);
      this._scheduleTick();
    }, intervalMs);
  }

  /**
   * Compute tick interval and events-per-tick based on current EPS.
   */
  _computeTickParams() {
    const eps = this.eps;

    if (eps <= 0.1) {
      // Very low: one event every 1/eps seconds (up to 10 seconds)
      return { intervalMs: Math.min(1000 / eps, 10000), eventsPerTick: 1 };
    }

    if (eps <= 50) {
      // Normal: one event per tick
      return { intervalMs: 1000 / eps, eventsPerTick: 1 };
    }

    // High EPS: batch events in ~10ms ticks
    const tickInterval = 10; // ms
    const rawPerTick = eps * (tickInterval / 1000);
    const eventsPerTick = Math.min(Math.max(1, Math.round(rawPerTick)), this.maxBatchSize);
    return { intervalMs: tickInterval, eventsPerTick };
  }

  /**
   * Execute a single tick: generate and emit the specified number of events.
   *
   * For fractional events-per-tick, uses an accumulator to achieve
   * accurate long-term rates.
   */
  _executeTick(targetCount) {
    if (!this.running || !this._generatorFn) return;

    const now = Date.now();
    this._lastTickTime = now;

    // For very precise EPS, accumulate fractional events
    this._fractionalAccumulator += targetCount;
    const actualCount = Math.floor(this._fractionalAccumulator);
    this._fractionalAccumulator -= actualCount;

    for (let i = 0; i < actualCount; i++) {
      if (!this.running) break;

      try {
        const event = this._generatorFn();
        if (event) {
          this._eventsGenerated++;
          if (event.raw) {
            this._bytesGenerated += Buffer.byteLength(event.raw, 'utf8');
          }
          if (this.onEvent) {
            this.onEvent(event);
          }
        }
      } catch (err) {
        if (this.onError) {
          this.onError(err);
        }
        // Continue generating; don't let one bad event stop the scheduler
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Utility
  // ---------------------------------------------------------------------------

  _formatUptime(ms) {
    const totalSeconds = Math.floor(ms / 1000);
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;

    if (hours > 0) {
      return `${hours}h ${minutes}m ${seconds}s`;
    }
    if (minutes > 0) {
      return `${minutes}m ${seconds}s`;
    }
    return `${seconds}s`;
  }
}

module.exports = { EventScheduler };
