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

// Pre-computed safe first octets for guaranteed O(1) public IP generation
const SAFE_FIRST_OCTETS = [];
for (let i = 1; i <= 223; i++) {
  if (!RESERVED_FIRST_OCTETS.has(i)) SAFE_FIRST_OCTETS.push(i);
}

function randomPublicIP(seed) {
  // Try the random approach first for good distribution
  let attempts = 0;
  while (attempts < 20) {
    const a = randomIntInRange(1, 223, seed !== undefined ? seed + attempts : undefined);
    if (!RESERVED_FIRST_OCTETS.has(a)) {
      const b = randomIntInRange(0, 255, seed !== undefined ? seed + attempts + 1 : undefined);
      const c = randomIntInRange(0, 255, seed !== undefined ? seed + attempts + 2 : undefined);
      const d = randomIntInRange(1, 254, seed !== undefined ? seed + attempts + 3 : undefined);
      return `${a}.${b}.${c}.${d}`;
    }
    attempts++;
  }
  // Fallback: pick from pre-computed safe octets instead of returning a static IP
  const a = pickRandom(SAFE_FIRST_OCTETS, seed !== undefined ? seed + 100 : undefined);
  const b = randomIntInRange(0, 255, seed !== undefined ? seed + 101 : undefined);
  const c = randomIntInRange(0, 255, seed !== undefined ? seed + 102 : undefined);
  const d = randomIntInRange(1, 254, seed !== undefined ? seed + 103 : undefined);
  return `${a}.${b}.${c}.${d}`;
}

const COMMON_PORTS = [
  { port: 20, service: 'ftp-data' },
  { port: 21, service: 'ftp' },
  { port: 22, service: 'ssh' },
  { port: 23, service: 'telnet' },
  { port: 25, service: 'smtp' },
  { port: 53, service: 'dns' },
  { port: 67, service: 'dhcp' },
  { port: 68, service: 'dhcp' },
  { port: 69, service: 'tftp' },
  { port: 80, service: 'http' },
  { port: 110, service: 'pop3' },
  { port: 111, service: 'rpc' },
  { port: 119, service: 'nntp' },
  { port: 123, service: 'ntp' },
  { port: 135, service: 'msrpc' },
  { port: 137, service: 'netbios-ns' },
  { port: 139, service: 'netbios-ssn' },
  { port: 143, service: 'imap' },
  { port: 161, service: 'snmp' },
  { port: 162, service: 'snmptrap' },
  { port: 389, service: 'ldap' },
  { port: 443, service: 'https' },
  { port: 445, service: 'microsoft-ds' },
  { port: 465, service: 'smtps' },
  { port: 514, service: 'syslog' },
  { port: 587, service: 'submission' },
  { port: 636, service: 'ldaps' },
  { port: 993, service: 'imaps' },
  { port: 995, service: 'pop3s' },
  { port: 1433, service: 'mssql' },
  { port: 1434, service: 'mssql-monitor' },
  { port: 1521, service: 'oracle' },
  { port: 2049, service: 'nfs' },
  { port: 3306, service: 'mysql' },
  { port: 3389, service: 'rdp' },
  { port: 5432, service: 'postgresql' },
  { port: 5900, service: 'vnc' },
  { port: 5985, service: 'winrm-http' },
  { port: 5986, service: 'winrm-https' },
  { port: 6379, service: 'redis' },
  { port: 8080, service: 'http-proxy' },
  { port: 8443, service: 'https-alt' },
  { port: 8888, service: 'http-alt' },
  { port: 9090, service: 'prometheus' },
  { port: 9200, service: 'elasticsearch' },
  { port: 9300, service: 'elasticsearch-transport' },
  { port: 11211, service: 'memcached' },
  { port: 27017, service: 'mongodb' },
];

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
  COMMON_PORTS,
};
