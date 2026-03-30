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
  // American / English
  'James', 'Mary', 'Robert', 'Patricia', 'John', 'Jennifer', 'Michael', 'Linda',
  'David', 'Elizabeth', 'William', 'Barbara', 'Richard', 'Susan', 'Joseph', 'Jessica',
  'Thomas', 'Sarah', 'Christopher', 'Karen', 'Charles', 'Lisa', 'Daniel', 'Nancy',
  'Matthew', 'Betty', 'Anthony', 'Margaret', 'Mark', 'Sandra', 'Donald', 'Ashley',
  'Steven', 'Kimberly', 'Paul', 'Emily', 'Andrew', 'Donna', 'Joshua', 'Michelle',
  'Kenneth', 'Carol', 'Kevin', 'Amanda', 'Brian', 'Dorothy', 'George', 'Melissa',
  'Timothy', 'Deborah', 'Ronald', 'Stephanie', 'Edward', 'Rebecca', 'Jason', 'Sharon',
  'Jeffrey', 'Laura', 'Ryan', 'Cynthia', 'Jacob', 'Kathleen', 'Gary', 'Amy',
  'Nicholas', 'Angela', 'Eric', 'Shirley', 'Jonathan', 'Anna', 'Stephen', 'Brenda',
  'Larry', 'Pamela', 'Justin', 'Emma', 'Scott', 'Nicole', 'Brandon', 'Helen',
  'Benjamin', 'Samantha', 'Samuel', 'Katherine', 'Raymond', 'Christine', 'Gregory', 'Debra',
  'Frank', 'Rachel', 'Alexander', 'Carolyn', 'Patrick', 'Janet', 'Jack', 'Catherine',
  'Dennis', 'Maria', 'Jerry', 'Heather', 'Tyler', 'Diane', 'Aaron', 'Ruth',
  'Nathan', 'Julie', 'Adam', 'Olivia', 'Henry', 'Joyce', 'Douglas', 'Virginia',
  'Peter', 'Victoria', 'Zachary', 'Kelly', 'Kyle', 'Lauren', 'Noah', 'Christina',
  // Hispanic / Latin
  'Carlos', 'Rosa', 'Miguel', 'Carmen', 'Luis', 'Elena', 'Jorge', 'Sofia',
  'Alejandro', 'Valentina', 'Diego', 'Isabella', 'Fernando', 'Lucia', 'Rafael', 'Camila',
  'Ricardo', 'Gabriela', 'Andres', 'Mariana', 'Pedro', 'Daniela', 'Pablo', 'Ana',
  'Sergio', 'Adriana', 'Raul', 'Natalia',
  // European
  'Jean', 'Marie', 'Pierre', 'Sophie', 'Luca', 'Chiara', 'Marco', 'Giulia',
  'Hans', 'Greta', 'Klaus', 'Ingrid', 'Sven', 'Astrid', 'Erik', 'Elsa',
  'Anton', 'Katarina', 'Ivan', 'Olga', 'Dmitri', 'Tatiana', 'Nikolai', 'Svetlana',
  'Jan', 'Marta', 'Piotr', 'Ewa', 'Tomas', 'Petra',
  // Asian
  'Wei', 'Mei', 'Hiroshi', 'Yuki', 'Takeshi', 'Sakura', 'Kenji', 'Aiko',
  'Jian', 'Ling', 'Chen', 'Xia', 'Ravi', 'Priya', 'Arjun', 'Ananya',
  'Raj', 'Deepa', 'Amit', 'Sunita', 'Min', 'Soo', 'Jin', 'Hana',
  'Tran', 'Linh', 'Nguyen', 'Thao', 'Suresh', 'Kavita',
  // African
  'Kwame', 'Amina', 'Kofi', 'Fatima', 'Ibrahim', 'Zainab', 'Omar', 'Aisha',
  'Moussa', 'Nadia', 'Yusuf', 'Khadija', 'Abdi', 'Halima', 'Tariq', 'Layla',
  'Chidi', 'Ngozi', 'Emeka', 'Adaeze',
  // Middle Eastern
  'Ali', 'Leila', 'Hassan', 'Sara', 'Mohammed', 'Yasmin', 'Ahmad', 'Noura',
  'Khalid', 'Rania', 'Samir', 'Dina',
];

const LAST_NAMES = [
  // American / English common
  'Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis',
  'Rodriguez', 'Martinez', 'Hernandez', 'Lopez', 'Gonzalez', 'Wilson', 'Anderson',
  'Thomas', 'Taylor', 'Moore', 'Jackson', 'Martin', 'Lee', 'Perez', 'Thompson',
  'White', 'Harris', 'Sanchez', 'Clark', 'Ramirez', 'Lewis', 'Robinson', 'Walker',
  'Young', 'Allen', 'King', 'Wright', 'Scott', 'Torres', 'Nguyen', 'Hill',
  'Flores', 'Green', 'Adams', 'Nelson', 'Baker', 'Hall', 'Rivera', 'Campbell',
  'Mitchell', 'Carter', 'Roberts', 'Turner', 'Phillips', 'Parker', 'Evans', 'Edwards',
  'Collins', 'Stewart', 'Morris', 'Murphy', 'Cook', 'Rogers', 'Morgan', 'Peterson',
  'Cooper', 'Reed', 'Bailey', 'Bell', 'Gomez', 'Kelly', 'Howard', 'Ward',
  'Cox', 'Diaz', 'Richardson', 'Wood', 'Watson', 'Brooks', 'Bennett', 'Gray',
  'James', 'Reyes', 'Cruz', 'Hughes', 'Price', 'Myers', 'Long', 'Foster',
  'Sanders', 'Ross', 'Morales', 'Powell', 'Sullivan', 'Russell', 'Ortiz', 'Jenkins',
  'Gutierrez', 'Perry', 'Butler', 'Barnes', 'Fisher', 'Henderson', 'Coleman', 'Simmons',
  'Patterson', 'Jordan', 'Reynolds', 'Hamilton', 'Graham', 'Kim', 'Gonzales', 'Alexander',
  'Ramos', 'Wallace', 'Griffin', 'West', 'Cole', 'Hayes', 'Chavez', 'Gibson',
  // European
  'Mueller', 'Schmidt', 'Schneider', 'Fischer', 'Weber', 'Meyer', 'Wagner', 'Becker',
  'Schulz', 'Hoffmann', 'Dupont', 'Bernard', 'Leroy', 'Moreau', 'Laurent',
  'Rossi', 'Russo', 'Ferrari', 'Bianchi', 'Romano', 'Colombo', 'Johansson', 'Lindberg',
  'Eriksson', 'Larsson', 'Nilsson', 'Kowalski', 'Nowak', 'Wojcik', 'Ivanov',
  'Petrov', 'Sokolov', 'Volkov', 'Popov', 'Novak', 'Horvat',
  // Asian
  'Wang', 'Zhang', 'Li', 'Liu', 'Chen', 'Yang', 'Huang', 'Wu', 'Zhou', 'Xu',
  'Tanaka', 'Suzuki', 'Takahashi', 'Watanabe', 'Ito', 'Yamamoto', 'Nakamura', 'Sato',
  'Park', 'Choi', 'Jung', 'Kang', 'Cho', 'Yoon',
  'Patel', 'Sharma', 'Singh', 'Kumar', 'Gupta', 'Mehta', 'Joshi', 'Verma',
  'Tran', 'Pham', 'Hoang', 'Bui',
  // Hispanic
  'Reyes', 'Mendoza', 'Vargas', 'Castillo', 'Jimenez', 'Romero', 'Alvarez', 'Ruiz',
  'Delgado', 'Aguilar', 'Medina', 'Soto', 'Herrera', 'Guerrero', 'Vega', 'Salazar',
  // African
  'Okafor', 'Adeyemi', 'Mensah', 'Osei', 'Diallo', 'Toure', 'Traore', 'Nkomo',
  'Moyo', 'Dlamini',
  // Middle Eastern
  'Hassan', 'Ahmed', 'Ali', 'Khan', 'Malik', 'Hussain', 'Rahman', 'Ibrahim',
];

const ADJECTIVES = [
  'brave', 'swift', 'silent', 'dark', 'bright', 'calm', 'fierce', 'noble',
  'vivid', 'bold', 'keen', 'rapid', 'warm', 'cool', 'sharp', 'quiet',
  'wild', 'free', 'pure', 'wise', 'agile', 'crimson', 'golden', 'silver',
  'iron', 'steel', 'amber', 'azure', 'cosmic', 'cyber', 'digital', 'electric',
  'frozen', 'ghost', 'hidden', 'jade', 'lunar', 'mighty', 'neon', 'obsidian',
  'phantom', 'primal', 'quantum', 'rouge', 'savage', 'shadow', 'sonic', 'stealth',
  'tactical', 'turbo', 'ultra', 'vapor', 'velvet', 'venom', 'viral', 'wicked',
  'zero', 'alpha', 'delta', 'omega', 'apex', 'prime', 'rogue', 'titan',
];

const NOUNS = [
  'falcon', 'tiger', 'phoenix', 'wolf', 'eagle', 'panther', 'hawk', 'raven',
  'cobra', 'viper', 'orca', 'lynx', 'fox', 'bear', 'lion', 'shark',
  'dragon', 'storm', 'frost', 'blaze', 'atlas', 'blade', 'bolt', 'canyon',
  'cipher', 'comet', 'condor', 'coyote', 'crown', 'dagger', 'ember', 'fang',
  'flame', 'forge', 'griffin', 'hammer', 'hornet', 'hydra', 'jaguar', 'kraken',
  'lance', 'mantis', 'mustang', 'nebula', 'nexus', 'osprey', 'puma', 'python',
  'raptor', 'saber', 'scorpion', 'sentinel', 'serpent', 'sparrow', 'specter', 'sphinx',
  'stallion', 'talon', 'tempest', 'thunder', 'trident', 'valkyrie', 'warden', 'wraith',
];

const DEPARTMENTS = [
  'engineering', 'security', 'ops', 'finance', 'sales', 'marketing',
  'hr', 'legal', 'support', 'devops', 'infrastructure', 'platform',
  'data-science', 'analytics', 'product', 'design', 'qa', 'release-eng',
  'sre', 'compliance', 'audit', 'procurement', 'facilities',
  'research', 'customer-success', 'partnerships', 'executive',
];

const LOCATIONS = [
  'NYC', 'LAX', 'CHI', 'DFW', 'SEA', 'SFO', 'BOS', 'ATL', 'DEN', 'MIA',
  'IAD', 'PHX', 'PDX', 'MSP', 'DTW', 'IAH', 'AUS', 'SLC', 'CLT', 'PHL',
  'LHR', 'FRA', 'AMS', 'CDG', 'DUB', 'ARN', 'ZRH', 'NRT', 'SIN', 'SYD',
  'BOM', 'ICN', 'HKG', 'GRU', 'YYZ',
];

const ROLES = [
  'WKS', 'SRV', 'DB', 'WEB', 'APP', 'FW', 'LB', 'DNS', 'VPN', 'NAS',
  'API', 'GW', 'PROXY', 'MQ', 'CACHE', 'LOG', 'MON', 'CI', 'SCAN',
  'MAIL', 'AUTH', 'FS', 'HPC', 'GPU', 'K8S', 'VAULT', 'SIEM',
];

const TLDS = [
  'com', 'net', 'org', 'io', 'co', 'dev', 'app', 'tech', 'cloud', 'systems',
  'info', 'biz', 'us', 'uk', 'de', 'eu', 'ai', 'solutions', 'digital',
  'global', 'group', 'services', 'security', 'network', 'company', 'software',
];

const DOMAIN_WORDS = [
  'acme', 'globex', 'initech', 'umbrella', 'stark', 'wayne', 'oscorp', 'cyberdyne',
  'aperture', 'soylent', 'massive', 'dynamic', 'vertex', 'nexus', 'quantum', 'cipher',
  'synth', 'nova', 'arc', 'pulse', 'apex', 'atlas', 'aurora', 'beacon',
  'bridge', 'carbon', 'catalyst', 'centauri', 'cirrus', 'cobalt', 'compass',
  'core', 'cortex', 'crimson', 'crux', 'dataflow', 'delta', 'echo',
  'ember', 'envoy', 'epoch', 'falcon', 'flux', 'forge', 'frontier',
  'fusion', 'granite', 'harbor', 'helix', 'horizon', 'hyperion', 'ionic',
  'iron', 'keystone', 'lattice', 'lunar', 'mantis', 'matrix', 'meridian',
  'meteor', 'nebula', 'nimbus', 'oasis', 'omega', 'onyx', 'orbit',
  'oxide', 'paladin', 'pinnacle', 'prism', 'radiant', 'relay', 'ridge',
  'ripple', 'rover', 'scalar', 'sentinel', 'sierra', 'signal', 'solar',
  'spark', 'spectra', 'sphere', 'stratus', 'summit', 'swift', 'tango',
  'terra', 'titan', 'trident', 'vector', 'venture', 'vortex', 'zenith',
];

const OS_LIST = [
  // Windows desktop
  'Windows NT 10.0; Win64; x64',
  'Windows NT 10.0; WOW64',
  'Windows NT 6.1; Win64; x64',
  'Windows NT 6.3; Win64; x64',
  'Windows NT 11.0; Win64; x64',
  // macOS
  'Macintosh; Intel Mac OS X 10_15_7',
  'Macintosh; Intel Mac OS X 13_4',
  'Macintosh; Intel Mac OS X 14_2_1',
  'Macintosh; Intel Mac OS X 14_5',
  'Macintosh; Apple M1 Mac OS X 14_3',
  'Macintosh; Apple M2 Mac OS X 15_0',
  // Linux
  'X11; Linux x86_64',
  'X11; Ubuntu; Linux x86_64',
  'X11; Fedora; Linux x86_64',
  'X11; CentOS; Linux x86_64',
  'X11; Linux aarch64',
  // Mobile - Android
  'Linux; Android 13; Pixel 7',
  'Linux; Android 14; SM-S918B',
  'Linux; Android 13; SM-A546B',
  'Linux; Android 12; Redmi Note 11',
  // Mobile - iOS
  'iPhone; CPU iPhone OS 17_4 like Mac OS X',
  'iPhone; CPU iPhone OS 16_6 like Mac OS X',
  'iPad; CPU OS 17_3 like Mac OS X',
];

const BROWSER_TEMPLATES = [
  // Chrome desktop
  { engine: 'AppleWebKit/537.36', browser: 'Chrome', vMin: 100, vMax: 126, suffix: 'Safari/537.36' },
  // Edge desktop
  { engine: 'AppleWebKit/537.36', browser: 'Chrome', vMin: 100, vMax: 126, suffix: 'Safari/537.36 Edg/${v}.0.${sv}.${patch}' },
  // Firefox desktop
  { engine: 'Gecko/20100101', browser: 'Firefox', vMin: 100, vMax: 127, suffix: '' },
  // Safari desktop
  { engine: 'AppleWebKit/605.1.15', browser: 'Version', vMin: 15, vMax: 17, suffix: 'Safari/605.1.15' },
  // Chrome mobile
  { engine: 'AppleWebKit/537.36', browser: 'Chrome', vMin: 110, vMax: 126, suffix: 'Mobile Safari/537.36' },
  // Safari mobile
  { engine: 'AppleWebKit/605.1.15', browser: 'Version', vMin: 16, vMax: 17, suffix: 'Mobile/15E148 Safari/604.1' },
  // Samsung browser
  { engine: 'AppleWebKit/537.36', browser: 'Chrome', vMin: 110, vMax: 126, suffix: 'Safari/537.36 SamsungBrowser/24.0' },
  // Opera
  { engine: 'AppleWebKit/537.36', browser: 'Chrome', vMin: 110, vMax: 126, suffix: 'Safari/537.36 OPR/${v}.0.0.0' },
  // Brave
  { engine: 'AppleWebKit/537.36', browser: 'Chrome', vMin: 110, vMax: 126, suffix: 'Safari/537.36 Brave/${v}' },
  // Vivaldi
  { engine: 'AppleWebKit/537.36', browser: 'Chrome', vMin: 110, vMax: 126, suffix: 'Safari/537.36 Vivaldi/6.${sv}' },
  // curl (non-Mozilla UA)
  { engine: 'curl', browser: 'curl', vMin: 7, vMax: 8, suffix: '' },
  // python-requests (non-Mozilla UA)
  { engine: 'python-requests', browser: 'python-requests', vMin: 2, vMax: 2, suffix: '' },
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
  const tmpl = pickRandom(BROWSER_TEMPLATES, seed !== undefined ? seed + 1 : undefined);
  const majorVersion = randomIntInRange(tmpl.vMin, tmpl.vMax, seed !== undefined ? seed + 2 : undefined);
  const sv = randomIntInRange(0, 99, seed !== undefined ? seed + 3 : undefined);
  const patch = randomIntInRange(0, 9999, seed !== undefined ? seed + 4 : undefined);

  // Non-Mozilla user agents (curl, python-requests, etc.)
  if (tmpl.engine === 'curl') {
    const minor = randomIntInRange(50, 88, seed !== undefined ? seed + 5 : undefined);
    return `curl/${majorVersion}.${minor}.0`;
  }
  if (tmpl.engine === 'python-requests') {
    const minor = randomIntInRange(20, 32, seed !== undefined ? seed + 5 : undefined);
    return `python-requests/${majorVersion}.${minor}.0`;
  }

  const os = pickRandom(OS_LIST, seed);

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

// ---------------------------------------------------------------------------
// Procedural generators — infinite uniqueness from tiny seed data
// ---------------------------------------------------------------------------

// Syllable combinator: 18 prefixes × 20 suffixes = 360 base names per gender
// Combined with pool names: 240 + 360 = 600 first names, zero extra bloat
const NAME_PREFIXES = ['Al', 'Br', 'Ca', 'Da', 'El', 'Fa', 'Ga', 'Ha', 'Ja', 'Ka', 'La', 'Ma', 'Na', 'Ra', 'Sa', 'Ta', 'Va', 'Za'];
const NAME_SUFFIXES = ['an', 'en', 'in', 'on', 'ar', 'er', 'ir', 'or', 'ay', 'ey', 'ia', 'ea', 'is', 'us', 'el', 'al', 'yn', 'lyn', 'ston', 'den'];

function proceduralName(seed) {
  const p = pickRandom(NAME_PREFIXES, seed);
  const s = pickRandom(NAME_SUFFIXES, seed !== undefined ? seed + 7 : undefined);
  return p + s;
}

// Procedural hostname: 27 roles × 35 locations × 9999 numbers = 9.4M unique hostnames
// Plus optional department and rack suffixes for even more variety
function proceduralHostname(seed) {
  const role = pickRandom(ROLES, seed);
  const loc = pickRandom(LOCATIONS, seed !== undefined ? seed + 1 : undefined);
  const num = randomIntInRange(1, 9999, seed !== undefined ? seed + 2 : undefined);
  const rack = randomIntInRange(1, 12, seed !== undefined ? seed + 3 : undefined);
  // 50% chance to include rack designator
  if (num % 2 === 0) {
    return `${role}-${loc}-R${rack}-${String(num).padStart(4, '0')}`;
  }
  return `${role}-${loc}-${String(num).padStart(4, '0')}`;
}

// Procedural serial number: prefix + random digits = millions of unique serials
function proceduralSerial(prefix, digitCount, seed) {
  prefix = prefix || '00725100';
  digitCount = digitCount || 7;
  const max = Math.pow(10, digitCount) - 1;
  const num = randomIntInRange(0, max, seed);
  return prefix + String(num).padStart(digitCount, '0');
}

// Procedural domain: 94 words × 26 TLDs × optional 2-word combos = 57k+ domains
function proceduralDomainCombo(seed) {
  const w1 = pickRandom(DOMAIN_WORDS, seed);
  const w2 = pickRandom(DOMAIN_WORDS, seed !== undefined ? seed + 3 : undefined);
  const tld = pickRandom(TLDS, seed !== undefined ? seed + 5 : undefined);
  // 40% chance of compound domain
  if ((seed !== undefined ? seed : crypto.randomInt(10)) % 10 < 4) {
    return `${w1}${w2}.${tld}`;
  }
  return `${w1}.${tld}`;
}

// Enhanced username: mixes pool names + procedural names for max diversity
function randomUsernameEnhanced(pattern, seed) {
  // 30% chance to use procedural name instead of pool
  const useProcedural = crypto.randomInt(10) < 3;
  const first = useProcedural ? proceduralName(seed) : pickRandom(FIRST_NAMES, seed);
  const last = pickRandom(LAST_NAMES, seed !== undefined ? seed + 1 : undefined);

  switch (pattern) {
    case 'firstinitial.last':
      return `${first[0].toLowerCase()}.${last.toLowerCase()}`;
    case 'adjective-noun-number': {
      const adj = pickRandom(ADJECTIVES, seed);
      const noun = pickRandom(NOUNS, seed !== undefined ? seed + 1 : undefined);
      const num = randomIntInRange(1, 9999, seed !== undefined ? seed + 2 : undefined);
      return `${adj}-${noun}-${num}`;
    }
    case 'first.last':
    default:
      return `${first.toLowerCase()}.${last.toLowerCase()}`;
  }
}

module.exports = {
  randomUsername: randomUsernameEnhanced,
  randomHostname,
  randomEmail,
  randomDomain,
  randomUserAgent,
  proceduralName,
  proceduralHostname,
  proceduralSerial,
  proceduralDomainCombo,
  FIRST_NAMES,
  LAST_NAMES,
  ADJECTIVES,
  NOUNS,
  DEPARTMENTS,
  LOCATIONS,
};
