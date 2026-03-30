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

function pickRandom(arr, seed) {
  if (seed !== undefined) {
    const rng = seededRNG(seed);
    return arr[Math.floor(rng(0, arr.length))];
  }
  return arr[crypto.randomInt(arr.length)];
}

function weightedChoice(items, weights, seed) {
  const total = weights.reduce((a, b) => a + b, 0);
  let r;
  if (seed !== undefined) {
    const rng = seededRNG(seed);
    r = rng(0, total);
  } else {
    r = Math.random() * total;
  }
  let cumulative = 0;
  for (let i = 0; i < items.length; i++) {
    cumulative += weights[i];
    if (r < cumulative) return items[i];
  }
  return items[items.length - 1];
}

function ipToInt(ip) {
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function intToIP(int) {
  return [
    (int >>> 24) & 0xff,
    (int >>> 16) & 0xff,
    (int >>> 8) & 0xff,
    int & 0xff,
  ].join('.');
}

function cidrToRange(cidr) {
  const [ip, prefixStr] = cidr.split('/');
  const prefix = parseInt(prefixStr, 10);
  const ipInt = ipToInt(ip);
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const start = (ipInt & mask) >>> 0;
  const end = (start | (~mask >>> 0)) >>> 0;
  return { start, end };
}

function randomIntInRange(min, max, seed) {
  if (seed !== undefined) {
    const rng = seededRNG(seed);
    return Math.floor(rng(min, max + 1));
  }
  return crypto.randomInt(min, max + 1);
}

function randomIPv4(cidr, seed) {
  if (cidr) {
    const { start, end } = cidrToRange(cidr);
    const ip = randomIntInRange(start, end, seed);
    return intToIP(ip);
  }
  const a = randomIntInRange(1, 254, seed);
  const b = randomIntInRange(0, 255, seed !== undefined ? seed + 1 : undefined);
  const c = randomIntInRange(0, 255, seed !== undefined ? seed + 2 : undefined);
  const d = randomIntInRange(1, 254, seed !== undefined ? seed + 3 : undefined);
  return `${a}.${b}.${c}.${d}`;
}

function randomIPv4Weighted(config, seed) {
  const entries = [];
  const weights = [];

  if (config.internal) {
    for (const item of config.internal) {
      entries.push({ cidr: item.cidr, type: 'internal' });
      weights.push(item.weight);
    }
  }
  if (config.external) {
    for (const item of config.external) {
      entries.push({ cidr: item.cidr, type: 'external' });
      weights.push(item.weight);
    }
  }

  const chosen = weightedChoice(entries, weights, seed);
  return randomIPv4(chosen.cidr, seed);
}

function randomMAC(seed) {
  const bytes = [];
  for (let i = 0; i < 6; i++) {
    bytes.push(randomIntInRange(0, 255, seed !== undefined ? seed + i : undefined));
  }
  bytes[0] = bytes[0] & 0xfe;
  return bytes.map((b) => b.toString(16).padStart(2, '0')).join(':');
}

function randomPort(type, seed) {
  switch (type) {
    case 'well-known':
      return randomIntInRange(1, 1023, seed);
    case 'registered':
      return randomIntInRange(1024, 49151, seed);
    case 'ephemeral':
      return randomIntInRange(49152, 65535, seed);
    default:
      return randomIntInRange(1, 65535, seed);
  }
}

const RFC1918_RANGES = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];

function randomPrivateIP(seed) {
  const cidr = pickRandom(RFC1918_RANGES, seed);
  return randomIPv4(cidr, seed);
}

const RESERVED_FIRST_OCTETS = new Set([0, 10, 100, 127, 169, 172, 192, 198, 203, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255]);

function randomPublicIP(seed) {
  let attempts = 0;
  while (attempts < 100) {
    const a = randomIntInRange(1, 223, seed !== undefined ? seed + attempts : undefined);
    if (!RESERVED_FIRST_OCTETS.has(a)) {
      const b = randomIntInRange(0, 255, seed !== undefined ? seed + attempts + 1 : undefined);
      const c = randomIntInRange(0, 255, seed !== undefined ? seed + attempts + 2 : undefined);
      const d = randomIntInRange(1, 254, seed !== undefined ? seed + attempts + 3 : undefined);
      return `${a}.${b}.${c}.${d}`;
    }
    attempts++;
  }
  return '8.8.8.8';
}

module.exports = {
  randomIPv4,
  randomIPv4Weighted,
  randomMAC,
  randomPort,
  randomPrivateIP,
  randomPublicIP,
  cidrToRange,
  intToIP,
  ipToInt,
  weightedChoice,
  pickRandom,
};
