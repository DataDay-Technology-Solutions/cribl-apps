'use strict';

const crypto = require('crypto');
const network = require('./network');
const identity = require('./identity');
const temporal = require('./temporal');
const security = require('./security');
const geo = require('./geo');

function pickRandom(arr, seed) {
  if (seed !== undefined) {
    return network.pickRandom(arr, seed);
  }
  return arr[crypto.randomInt(arr.length)];
}

module.exports = {
  pickRandom,
  weightedChoice: network.weightedChoice,

  randomIPv4: network.randomIPv4,
  randomIPv4Weighted: network.randomIPv4Weighted,
  randomMAC: network.randomMAC,
  randomPort: network.randomPort,
  randomPrivateIP: network.randomPrivateIP,
  randomPublicIP: network.randomPublicIP,
  cidrToRange: network.cidrToRange,
  intToIP: network.intToIP,
  ipToInt: network.ipToInt,

  randomUsername: identity.randomUsername,
  randomHostname: identity.randomHostname,
  randomEmail: identity.randomEmail,
  randomDomain: identity.randomDomain,
  randomUserAgent: identity.randomUserAgent,
  proceduralName: identity.proceduralName,
  proceduralHostname: identity.proceduralHostname,
  proceduralSerial: identity.proceduralSerial,
  proceduralDomainCombo: identity.proceduralDomainCombo,
  FIRST_NAMES: identity.FIRST_NAMES,
  LAST_NAMES: identity.LAST_NAMES,
  ADJECTIVES: identity.ADJECTIVES,
  NOUNS: identity.NOUNS,
  DEPARTMENTS: identity.DEPARTMENTS,
  LOCATIONS: identity.LOCATIONS,

  randomTimestamp: temporal.randomTimestamp,
  businessHoursTimestamp: temporal.businessHoursTimestamp,
  burstTimestamps: temporal.burstTimestamps,
  realisticJitter: temporal.realisticJitter,
  formatTimestamp: temporal.formatTimestamp,

  randomUUID: security.randomUUID,
  randomSHA256: security.randomSHA256,
  randomMD5: security.randomMD5,
  randomSessionID: security.randomSessionID,
  randomAPIKey: security.randomAPIKey,
  randomCVE: security.randomCVE,
  randomMITREAttackID: security.randomMITREAttackID,

  randomGeoIP: geo.randomGeoIP,
  geoForCIDR: geo.geoForCIDR,
  randomCountry: geo.randomCountry,
  randomCoordinates: geo.randomCoordinates,
  CITIES: geo.CITIES,

  network,
  identity,
  temporal,
  security,
  geo,
};
