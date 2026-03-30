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

function randomIntInRange(min, max, seed) {
  if (seed !== undefined) {
    const rng = seededRNG(seed);
    return Math.floor(rng(min, max + 1));
  }
  return crypto.randomInt(min, max + 1);
}

const FIRST_NAMES = [
  'James', 'Mary', 'Robert', 'Patricia', 'John', 'Jennifer', 'Michael', 'Linda',
  'David', 'Elizabeth', 'William', 'Barbara', 'Richard', 'Susan', 'Joseph', 'Jessica',
  'Thomas', 'Sarah', 'Christopher', 'Karen', 'Charles', 'Lisa', 'Daniel', 'Nancy',
  'Matthew', 'Betty', 'Anthony', 'Margaret', 'Mark', 'Sandra', 'Donald', 'Ashley',
  'Steven', 'Kimberly', 'Paul', 'Emily', 'Andrew', 'Donna', 'Joshua', 'Michelle',
  'Kenneth', 'Carol', 'Kevin', 'Amanda', 'Brian', 'Dorothy', 'George', 'Melissa',
  'Timothy', 'Deborah',
];

const LAST_NAMES = [
  'Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis',
  'Rodriguez', 'Martinez', 'Hernandez', 'Lopez', 'Gonzalez', 'Wilson', 'Anderson',
  'Thomas', 'Taylor', 'Moore', 'Jackson', 'Martin', 'Lee', 'Perez', 'Thompson',
  'White', 'Harris', 'Sanchez', 'Clark', 'Ramirez', 'Lewis', 'Robinson', 'Walker',
  'Young', 'Allen', 'King', 'Wright', 'Scott', 'Torres', 'Nguyen', 'Hill',
  'Flores', 'Green', 'Adams', 'Nelson', 'Baker', 'Hall', 'Rivera', 'Campbell',
  'Mitchell', 'Carter', 'Roberts',
];

const ADJECTIVES = [
  'brave', 'swift', 'silent', 'dark', 'bright', 'calm', 'fierce', 'noble',
  'vivid', 'bold', 'keen', 'rapid', 'warm', 'cool', 'sharp', 'quiet',
  'wild', 'free', 'pure', 'wise',
];

const NOUNS = [
  'falcon', 'tiger', 'phoenix', 'wolf', 'eagle', 'panther', 'hawk', 'raven',
  'cobra', 'viper', 'orca', 'lynx', 'fox', 'bear', 'lion', 'shark',
  'dragon', 'storm', 'frost', 'blaze',
];

const DEPARTMENTS = [
  'engineering', 'security', 'ops', 'finance', 'sales', 'marketing',
  'hr', 'legal', 'support', 'devops',
];

const LOCATIONS = [
  'NYC', 'LAX', 'CHI', 'DFW', 'SEA', 'SFO', 'BOS', 'ATL', 'DEN', 'MIA',
];

const ROLES = [
  'WKS', 'SRV', 'DB', 'WEB', 'APP', 'FW', 'LB', 'DNS', 'VPN', 'NAS',
];

const TLDS = [
  'com', 'net', 'org', 'io', 'co', 'dev', 'app', 'tech', 'cloud', 'systems',
];

const DOMAIN_WORDS = [
  'acme', 'globex', 'initech', 'umbrella', 'stark', 'wayne', 'oscorp', 'cyberdyne',
  'aperture', 'soylent', 'massive', 'dynamic', 'vertex', 'nexus', 'quantum', 'cipher',
  'synth', 'nova', 'arc', 'pulse',
];

const OS_LIST = [
  'Windows NT 10.0; Win64; x64',
  'Windows NT 10.0; WOW64',
  'Windows NT 6.1; Win64; x64',
  'Macintosh; Intel Mac OS X 10_15_7',
  'Macintosh; Intel Mac OS X 13_4',
  'Macintosh; Intel Mac OS X 14_2_1',
  'X11; Linux x86_64',
  'X11; Ubuntu; Linux x86_64',
];

const BROWSER_TEMPLATES = [
  { engine: 'AppleWebKit/537.36', browser: 'Chrome', vMin: 100, vMax: 124, suffix: 'Safari/537.36' },
  { engine: 'AppleWebKit/537.36', browser: 'Chrome', vMin: 90, vMax: 124, suffix: 'Safari/537.36 Edg/${v}.0.${sv}.${patch}' },
  { engine: 'Gecko/20100101', browser: 'Firefox', vMin: 100, vMax: 125, suffix: '' },
  { engine: 'AppleWebKit/605.1.15', browser: 'Version', vMin: 15, vMax: 17, suffix: 'Safari/605.1.15' },
];

function randomUsername(pattern, seed) {
  const first = pickRandom(FIRST_NAMES, seed);
  const last = pickRandom(LAST_NAMES, seed !== undefined ? seed + 1 : undefined);

  switch (pattern) {
    case 'firstinitial.last':
      return `${first[0].toLowerCase()}.${last.toLowerCase()}`;
    case 'adjective-noun-number': {
      const adj = pickRandom(ADJECTIVES, seed);
      const noun = pickRandom(NOUNS, seed !== undefined ? seed + 1 : undefined);
      const num = randomIntInRange(1, 999, seed !== undefined ? seed + 2 : undefined);
      return `${adj}-${noun}-${num}`;
    }
    case 'first.last':
    default:
      return `${first.toLowerCase()}.${last.toLowerCase()}`;
  }
}

function randomHostname(pattern, seed) {
  switch (pattern) {
    case 'adjective-noun': {
      const adj = pickRandom(ADJECTIVES, seed);
      const noun = pickRandom(NOUNS, seed !== undefined ? seed + 1 : undefined);
      return `${adj}-${noun}`;
    }
    case 'role-location-number':
    default: {
      const role = pickRandom(ROLES, seed);
      const loc = pickRandom(LOCATIONS, seed !== undefined ? seed + 1 : undefined);
      const num = randomIntInRange(1, 9999, seed !== undefined ? seed + 2 : undefined);
      return `${role}-${loc}-${String(num).padStart(4, '0')}`;
    }
  }
}

function randomDomain(seed) {
  const word = pickRandom(DOMAIN_WORDS, seed);
  const tld = pickRandom(TLDS, seed !== undefined ? seed + 1 : undefined);
  return `${word}.${tld}`;
}

function randomEmail(domain, seed) {
  const user = randomUsername('first.last', seed);
  const d = domain || randomDomain(seed !== undefined ? seed + 10 : undefined);
  return `${user}@${d}`;
}

function randomUserAgent(seed) {
  const os = pickRandom(OS_LIST, seed);
  const tmpl = pickRandom(BROWSER_TEMPLATES, seed !== undefined ? seed + 1 : undefined);
  const majorVersion = randomIntInRange(tmpl.vMin, tmpl.vMax, seed !== undefined ? seed + 2 : undefined);
  const sv = randomIntInRange(0, 99, seed !== undefined ? seed + 3 : undefined);
  const patch = randomIntInRange(0, 9999, seed !== undefined ? seed + 4 : undefined);

  if (tmpl.browser === 'Firefox') {
    return `Mozilla/5.0 (${os}; rv:${majorVersion}.0) ${tmpl.engine} Firefox/${majorVersion}.0`;
  }

  if (tmpl.browser === 'Version') {
    const minor = randomIntInRange(0, 6, seed !== undefined ? seed + 5 : undefined);
    return `Mozilla/5.0 (${os}) ${tmpl.engine} (KHTML, like Gecko) Version/${majorVersion}.${minor} ${tmpl.suffix}`;
  }

  let suffix = tmpl.suffix
    .replace('${v}', String(majorVersion))
    .replace('${sv}', String(sv))
    .replace('${patch}', String(patch));

  return `Mozilla/5.0 (${os}) ${tmpl.engine} (KHTML, like Gecko) Chrome/${majorVersion}.0.${sv}.${patch} ${suffix}`;
}

module.exports = {
  randomUsername,
  randomHostname,
  randomEmail,
  randomDomain,
  randomUserAgent,
  FIRST_NAMES,
  LAST_NAMES,
  ADJECTIVES,
  NOUNS,
  DEPARTMENTS,
  LOCATIONS,
};
