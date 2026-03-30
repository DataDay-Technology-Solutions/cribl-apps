'use strict';

const crypto = require('crypto');

function seededRNG(seed) {
  let s = typeof seed === 'number' ? seed : 0;
  for (let i = 0; i < String(seed).length; i++) {
    s = ((s << 5) - s + String(seed).charCodeAt(i)) | 0;
  }
  return function next(min = 0, max = 1) {
    s = (s * 1664525 + 1013904223) & 0x7fffffff;
    return min + (s / 0x7fffffff) * (max - min);
  };
}

function randomIntInRange(min, max, seed) {
  if (seed !== undefined) {
    const rng = seededRNG(seed);
    return Math.floor(rng(min, max + 1));
  }
  return crypto.randomInt(min, max + 1);
}

function randomFloat(min, max, seed) {
  if (seed !== undefined) {
    const rng = seededRNG(seed);
    return rng(min, max);
  }
  return min + Math.random() * (max - min);
}

const MONTHS_SHORT = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const DAYS_SHORT = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

function pad(n, len = 2) {
  return String(n).padStart(len, '0');
}

function formatTimestamp(date, format) {
  const d = date instanceof Date ? date : new Date(date);

  switch (format) {
    case 'epoch':
      return Math.floor(d.getTime() / 1000);

    case 'epoch_ms':
      return d.getTime();

    case 'syslog': {
      const mon = MONTHS_SHORT[d.getMonth()];
      const day = pad(d.getDate());
      const h = pad(d.getHours());
      const m = pad(d.getMinutes());
      const s = pad(d.getSeconds());
      return `${mon} ${day} ${h}:${m}:${s}`;
    }

    case 'cef': {
      const mon = MONTHS_SHORT[d.getMonth()];
      const day = pad(d.getDate());
      const y = d.getFullYear();
      const h = pad(d.getHours());
      const m = pad(d.getMinutes());
      const s = pad(d.getSeconds());
      const ms = pad(d.getMilliseconds(), 3);
      return `${mon} ${day} ${y} ${h}:${m}:${s}.${ms}`;
    }

    case 'apache': {
      const day = pad(d.getUTCDate());
      const mon = MONTHS_SHORT[d.getUTCMonth()];
      const y = d.getUTCFullYear();
      const h = pad(d.getUTCHours());
      const m = pad(d.getUTCMinutes());
      const s = pad(d.getUTCSeconds());
      return `[${day}/${mon}/${y}:${h}:${m}:${s} +0000]`;
    }

    case 'iso':
    default:
      return d.toISOString();
  }
}

function randomTimestamp(options, seed) {
  const opts = options || {};
  const base = opts.base ? new Date(opts.base).getTime() : Date.now();
  const jitterMs = opts.jitterMs || 0;
  const format = opts.format || 'iso';

  let ts = base;
  if (jitterMs > 0) {
    const offset = randomIntInRange(-jitterMs, jitterMs, seed);
    ts += offset;
  }

  return formatTimestamp(new Date(ts), format);
}

function businessHoursTimestamp(timezone, seed) {
  const now = new Date();
  const year = now.getFullYear();
  const month = now.getMonth();

  let day, hour;
  let attempts = 0;
  do {
    day = randomIntInRange(1, 28, seed !== undefined ? seed + attempts : undefined);
    const dow = new Date(year, month, day).getDay();
    hour = randomIntInRange(0, 23, seed !== undefined ? seed + attempts + 100 : undefined);
    attempts++;

    if (dow >= 1 && dow <= 5 && hour >= 8 && hour < 18) break;

    if (attempts > 50) {
      while (new Date(year, month, day).getDay() === 0 || new Date(year, month, day).getDay() === 6) {
        day = ((day) % 28) + 1;
      }
      hour = randomIntInRange(8, 17, seed !== undefined ? seed + 200 : undefined);
      break;
    }

    const weight = randomFloat(0, 1, seed !== undefined ? seed + attempts + 200 : undefined);
    if (dow >= 1 && dow <= 5 && hour >= 8 && hour < 18) break;
    if (weight < 0.85) continue;
    break;
  } while (true);

  const minute = randomIntInRange(0, 59, seed !== undefined ? seed + 300 : undefined);
  const second = randomIntInRange(0, 59, seed !== undefined ? seed + 301 : undefined);
  const ms = randomIntInRange(0, 999, seed !== undefined ? seed + 302 : undefined);

  return new Date(year, month, day, hour, minute, second, ms);
}

function burstTimestamps(count, windowMs, seed) {
  const base = Date.now();
  const timestamps = [];

  for (let i = 0; i < count; i++) {
    const offset = randomIntInRange(0, windowMs, seed !== undefined ? seed + i : undefined);
    timestamps.push(new Date(base + offset));
  }

  timestamps.sort((a, b) => a.getTime() - b.getTime());
  return timestamps;
}

function realisticJitter(baseMs, seed) {
  const factor = randomFloat(-0.2, 0.5, seed);
  return Math.round(baseMs * (1 + factor));
}

module.exports = {
  randomTimestamp,
  businessHoursTimestamp,
  burstTimestamps,
  realisticJitter,
  formatTimestamp,
};
