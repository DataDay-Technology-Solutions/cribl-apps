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

const HEX_CHARS = '0123456789abcdef';
const ALPHANUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

function randomHex(length, seed) {
  const chars = [];
  for (let i = 0; i < length; i++) {
    const idx = randomIntInRange(0, 15, seed !== undefined ? seed + i : undefined);
    chars.push(HEX_CHARS[idx]);
  }
  return chars.join('');
}

function randomAlphaNum(length, seed) {
  const chars = [];
  for (let i = 0; i < length; i++) {
    const idx = randomIntInRange(0, ALPHANUM.length - 1, seed !== undefined ? seed + i : undefined);
    chars.push(ALPHANUM[idx]);
  }
  return chars.join('');
}

function randomUUID(seed) {
  if (seed !== undefined) {
    const hex = randomHex(32, seed);
    return [
      hex.slice(0, 8),
      hex.slice(8, 12),
      '4' + hex.slice(13, 16),
      ((parseInt(hex[16], 16) & 0x3) | 0x8).toString(16) + hex.slice(17, 20),
      hex.slice(20, 32),
    ].join('-');
  }
  return crypto.randomUUID();
}

function randomSHA256(seed) {
  if (seed !== undefined) {
    return randomHex(64, seed);
  }
  return crypto.createHash('sha256').update(crypto.randomBytes(32)).digest('hex');
}

function randomMD5(seed) {
  if (seed !== undefined) {
    return randomHex(32, seed);
  }
  return crypto.createHash('md5').update(crypto.randomBytes(16)).digest('hex');
}

function randomSessionID(length, seed) {
  const len = length || 32;
  return randomAlphaNum(len, seed);
}

function randomAPIKey(prefix, seed) {
  const key = randomAlphaNum(48, seed);
  if (prefix) {
    return `${prefix}${key}`;
  }
  return key;
}

function randomCVE(seed) {
  const year = randomIntInRange(2020, 2025, seed);
  const id = randomIntInRange(1000, 49999, seed !== undefined ? seed + 1 : undefined);
  return `CVE-${year}-${id}`;
}

const MITRE_TECHNIQUES = [
  'T1001', 'T1003', 'T1005', 'T1007', 'T1010', 'T1011', 'T1012', 'T1016',
  'T1018', 'T1020', 'T1021', 'T1027', 'T1033', 'T1036', 'T1037', 'T1039',
  'T1040', 'T1041', 'T1046', 'T1047', 'T1048', 'T1049', 'T1053', 'T1055',
  'T1056', 'T1057', 'T1059', 'T1068', 'T1069', 'T1070', 'T1071', 'T1072',
  'T1074', 'T1078', 'T1080', 'T1082', 'T1083', 'T1087', 'T1090', 'T1095',
  'T1098', 'T1102', 'T1105', 'T1110', 'T1112', 'T1113', 'T1114', 'T1115',
  'T1119', 'T1120', 'T1123', 'T1125', 'T1127', 'T1129', 'T1132', 'T1133',
  'T1134', 'T1135', 'T1136', 'T1137', 'T1140', 'T1176', 'T1185', 'T1189',
  'T1190', 'T1195', 'T1197', 'T1199', 'T1200', 'T1201', 'T1202', 'T1203',
  'T1204', 'T1205', 'T1207', 'T1210', 'T1211', 'T1212', 'T1213', 'T1216',
  'T1217', 'T1218', 'T1219', 'T1220', 'T1221', 'T1222', 'T1480', 'T1482',
  'T1484', 'T1485', 'T1486', 'T1489', 'T1490', 'T1491', 'T1495', 'T1496',
  'T1497', 'T1498', 'T1499', 'T1505', 'T1518', 'T1525', 'T1528', 'T1529',
  'T1530', 'T1531', 'T1534', 'T1535', 'T1537', 'T1538', 'T1539', 'T1542',
  'T1543', 'T1546', 'T1547', 'T1548', 'T1550', 'T1552', 'T1553', 'T1554',
  'T1555', 'T1556', 'T1557', 'T1558', 'T1559', 'T1560', 'T1561', 'T1562',
  'T1563', 'T1564', 'T1565', 'T1566', 'T1567', 'T1568', 'T1569', 'T1570',
  'T1571', 'T1572', 'T1573', 'T1574', 'T1578', 'T1580', 'T1583', 'T1584',
  'T1585', 'T1586', 'T1587', 'T1588', 'T1589', 'T1590', 'T1591', 'T1592',
  'T1593', 'T1594', 'T1595', 'T1596', 'T1597', 'T1598', 'T1599', 'T1600',
  'T1601', 'T1602', 'T1606', 'T1608', 'T1609', 'T1610', 'T1611', 'T1612',
  'T1613', 'T1614', 'T1615', 'T1619', 'T1620', 'T1621', 'T1622',
];

function randomMITREAttackID(seed) {
  const technique = seed !== undefined
    ? MITRE_TECHNIQUES[Math.abs(seed) % MITRE_TECHNIQUES.length]
    : MITRE_TECHNIQUES[crypto.randomInt(MITRE_TECHNIQUES.length)];

  const hasSub = randomIntInRange(0, 1, seed !== undefined ? seed + 1 : undefined);
  if (hasSub) {
    const sub = randomIntInRange(1, 12, seed !== undefined ? seed + 2 : undefined);
    return `${technique}.${pad(sub, 3)}`;
  }
  return technique;
}

function pad(n, len) {
  return String(n).padStart(len, '0');
}

module.exports = {
  randomUUID,
  randomSHA256,
  randomMD5,
  randomSessionID,
  randomAPIKey,
  randomCVE,
  randomMITREAttackID,
};
