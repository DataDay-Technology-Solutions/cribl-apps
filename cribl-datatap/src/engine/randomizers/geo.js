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

function randomFloat(min, max, seed) {
  if (seed !== undefined) {
    const rng = seededRNG(seed);
    return rng(min, max);
  }
  return min + Math.random() * (max - min);
}

const CITIES = [
  { city: 'New York', region: 'New York', country: 'United States', countryCode: 'US', lat: 40.7128, lon: -74.0060, timezone: 'America/New_York' },
  { city: 'Los Angeles', region: 'California', country: 'United States', countryCode: 'US', lat: 33.9425, lon: -118.2551, timezone: 'America/Los_Angeles' },
  { city: 'Chicago', region: 'Illinois', country: 'United States', countryCode: 'US', lat: 41.8781, lon: -87.6298, timezone: 'America/Chicago' },
  { city: 'Houston', region: 'Texas', country: 'United States', countryCode: 'US', lat: 29.7604, lon: -95.3698, timezone: 'America/Chicago' },
  { city: 'Phoenix', region: 'Arizona', country: 'United States', countryCode: 'US', lat: 33.4484, lon: -112.0740, timezone: 'America/Phoenix' },
  { city: 'Dallas', region: 'Texas', country: 'United States', countryCode: 'US', lat: 32.7767, lon: -96.7970, timezone: 'America/Chicago' },
  { city: 'San Francisco', region: 'California', country: 'United States', countryCode: 'US', lat: 37.7749, lon: -122.4194, timezone: 'America/Los_Angeles' },
  { city: 'Seattle', region: 'Washington', country: 'United States', countryCode: 'US', lat: 47.6062, lon: -122.3321, timezone: 'America/Los_Angeles' },
  { city: 'Denver', region: 'Colorado', country: 'United States', countryCode: 'US', lat: 39.7392, lon: -104.9903, timezone: 'America/Denver' },
  { city: 'Atlanta', region: 'Georgia', country: 'United States', countryCode: 'US', lat: 33.7490, lon: -84.3880, timezone: 'America/New_York' },
  { city: 'Miami', region: 'Florida', country: 'United States', countryCode: 'US', lat: 25.7617, lon: -80.1918, timezone: 'America/New_York' },
  { city: 'Boston', region: 'Massachusetts', country: 'United States', countryCode: 'US', lat: 42.3601, lon: -71.0589, timezone: 'America/New_York' },
  { city: 'Washington', region: 'District of Columbia', country: 'United States', countryCode: 'US', lat: 38.9072, lon: -77.0369, timezone: 'America/New_York' },
  { city: 'Austin', region: 'Texas', country: 'United States', countryCode: 'US', lat: 30.2672, lon: -97.7431, timezone: 'America/Chicago' },
  { city: 'Portland', region: 'Oregon', country: 'United States', countryCode: 'US', lat: 45.5152, lon: -122.6784, timezone: 'America/Los_Angeles' },
  { city: 'London', region: 'England', country: 'United Kingdom', countryCode: 'GB', lat: 51.5074, lon: -0.1278, timezone: 'Europe/London' },
  { city: 'Frankfurt', region: 'Hesse', country: 'Germany', countryCode: 'DE', lat: 50.1109, lon: 8.6821, timezone: 'Europe/Berlin' },
  { city: 'Amsterdam', region: 'North Holland', country: 'Netherlands', countryCode: 'NL', lat: 52.3676, lon: 4.9041, timezone: 'Europe/Amsterdam' },
  { city: 'Paris', region: 'Ile-de-France', country: 'France', countryCode: 'FR', lat: 48.8566, lon: 2.3522, timezone: 'Europe/Paris' },
  { city: 'Dublin', region: 'Leinster', country: 'Ireland', countryCode: 'IE', lat: 53.3498, lon: -6.2603, timezone: 'Europe/Dublin' },
  { city: 'Stockholm', region: 'Stockholm', country: 'Sweden', countryCode: 'SE', lat: 59.3293, lon: 18.0686, timezone: 'Europe/Stockholm' },
  { city: 'Zurich', region: 'Zurich', country: 'Switzerland', countryCode: 'CH', lat: 47.3769, lon: 8.5417, timezone: 'Europe/Zurich' },
  { city: 'Tokyo', region: 'Tokyo', country: 'Japan', countryCode: 'JP', lat: 35.6762, lon: 139.6503, timezone: 'Asia/Tokyo' },
  { city: 'Singapore', region: 'Singapore', country: 'Singapore', countryCode: 'SG', lat: 1.3521, lon: 103.8198, timezone: 'Asia/Singapore' },
  { city: 'Sydney', region: 'New South Wales', country: 'Australia', countryCode: 'AU', lat: -33.8688, lon: 151.2093, timezone: 'Australia/Sydney' },
  { city: 'Mumbai', region: 'Maharashtra', country: 'India', countryCode: 'IN', lat: 19.0760, lon: 72.8777, timezone: 'Asia/Kolkata' },
  { city: 'Seoul', region: 'Seoul', country: 'South Korea', countryCode: 'KR', lat: 37.5665, lon: 126.9780, timezone: 'Asia/Seoul' },
  { city: 'Hong Kong', region: 'Hong Kong', country: 'Hong Kong', countryCode: 'HK', lat: 22.3193, lon: 114.1694, timezone: 'Asia/Hong_Kong' },
  { city: 'Sao Paulo', region: 'Sao Paulo', country: 'Brazil', countryCode: 'BR', lat: -23.5505, lon: -46.6333, timezone: 'America/Sao_Paulo' },
  { city: 'Toronto', region: 'Ontario', country: 'Canada', countryCode: 'CA', lat: 43.6532, lon: -79.3832, timezone: 'America/Toronto' },
];

const OCTET_TO_CITY_INDEX = {};
(function buildOctetMap() {
  const usable = [];
  for (let i = 1; i <= 223; i++) {
    if (i !== 10 && i !== 100 && i !== 127 && i !== 169 && i !== 172 && i !== 192) {
      usable.push(i);
    }
  }
  for (let i = 0; i < usable.length; i++) {
    OCTET_TO_CITY_INDEX[usable[i]] = i % CITIES.length;
  }
})();

function randomGeoIP(ip, seed) {
  if (ip) {
    const firstOctet = parseInt(ip.split('.')[0], 10);
    const idx = OCTET_TO_CITY_INDEX[firstOctet];
    if (idx !== undefined) {
      const c = CITIES[idx];
      return {
        country: c.country,
        countryCode: c.countryCode,
        city: c.city,
        region: c.region,
        lat: c.lat,
        lon: c.lon,
        timezone: c.timezone,
      };
    }
  }

  const c = pickRandom(CITIES, seed);
  return {
    country: c.country,
    countryCode: c.countryCode,
    city: c.city,
    region: c.region,
    lat: c.lat,
    lon: c.lon,
    timezone: c.timezone,
  };
}

function ipToInt(ip) {
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function geoForCIDR(cidr, seed) {
  const [ip] = cidr.split('/');
  const firstOctet = parseInt(ip.split('.')[0], 10);
  const idx = OCTET_TO_CITY_INDEX[firstOctet];
  if (idx !== undefined) {
    const c = CITIES[idx];
    return {
      country: c.country,
      countryCode: c.countryCode,
      city: c.city,
      region: c.region,
      lat: c.lat,
      lon: c.lon,
      timezone: c.timezone,
    };
  }
  return randomGeoIP(undefined, seed);
}

function randomCountry(seed) {
  const c = pickRandom(CITIES, seed);
  return { country: c.country, countryCode: c.countryCode };
}

function randomCoordinates(near, seed) {
  if (near) {
    const latJitter = randomFloat(-0.5, 0.5, seed);
    const lonJitter = randomFloat(-0.5, 0.5, seed !== undefined ? seed + 1 : undefined);
    return {
      lat: Math.round((near.lat + latJitter) * 10000) / 10000,
      lon: Math.round((near.lon + lonJitter) * 10000) / 10000,
    };
  }
  const lat = randomFloat(-90, 90, seed);
  const lon = randomFloat(-180, 180, seed !== undefined ? seed + 1 : undefined);
  return {
    lat: Math.round(lat * 10000) / 10000,
    lon: Math.round(lon * 10000) / 10000,
  };
}

module.exports = {
  randomGeoIP,
  geoForCIDR,
  randomCountry,
  randomCoordinates,
  CITIES,
};
