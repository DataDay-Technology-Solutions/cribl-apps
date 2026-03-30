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
  // United States (25)
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
  { city: 'San Jose', region: 'California', country: 'United States', countryCode: 'US', lat: 37.3382, lon: -121.8863, timezone: 'America/Los_Angeles' },
  { city: 'Las Vegas', region: 'Nevada', country: 'United States', countryCode: 'US', lat: 36.1699, lon: -115.1398, timezone: 'America/Los_Angeles' },
  { city: 'Minneapolis', region: 'Minnesota', country: 'United States', countryCode: 'US', lat: 44.9778, lon: -93.2650, timezone: 'America/Chicago' },
  { city: 'Detroit', region: 'Michigan', country: 'United States', countryCode: 'US', lat: 42.3314, lon: -83.0458, timezone: 'America/Detroit' },
  { city: 'Salt Lake City', region: 'Utah', country: 'United States', countryCode: 'US', lat: 40.7608, lon: -111.8910, timezone: 'America/Denver' },
  { city: 'Charlotte', region: 'North Carolina', country: 'United States', countryCode: 'US', lat: 35.2271, lon: -80.8431, timezone: 'America/New_York' },
  { city: 'Nashville', region: 'Tennessee', country: 'United States', countryCode: 'US', lat: 36.1627, lon: -86.7816, timezone: 'America/Chicago' },
  { city: 'Philadelphia', region: 'Pennsylvania', country: 'United States', countryCode: 'US', lat: 39.9526, lon: -75.1652, timezone: 'America/New_York' },
  { city: 'San Diego', region: 'California', country: 'United States', countryCode: 'US', lat: 32.7157, lon: -117.1611, timezone: 'America/Los_Angeles' },
  { city: 'Raleigh', region: 'North Carolina', country: 'United States', countryCode: 'US', lat: 35.7796, lon: -78.6382, timezone: 'America/New_York' },
  // Canada (3)
  { city: 'Toronto', region: 'Ontario', country: 'Canada', countryCode: 'CA', lat: 43.6532, lon: -79.3832, timezone: 'America/Toronto' },
  { city: 'Vancouver', region: 'British Columbia', country: 'Canada', countryCode: 'CA', lat: 49.2827, lon: -123.1207, timezone: 'America/Vancouver' },
  { city: 'Montreal', region: 'Quebec', country: 'Canada', countryCode: 'CA', lat: 45.5017, lon: -73.5673, timezone: 'America/Montreal' },
  // Europe (25)
  { city: 'London', region: 'England', country: 'United Kingdom', countryCode: 'GB', lat: 51.5074, lon: -0.1278, timezone: 'Europe/London' },
  { city: 'Frankfurt', region: 'Hesse', country: 'Germany', countryCode: 'DE', lat: 50.1109, lon: 8.6821, timezone: 'Europe/Berlin' },
  { city: 'Amsterdam', region: 'North Holland', country: 'Netherlands', countryCode: 'NL', lat: 52.3676, lon: 4.9041, timezone: 'Europe/Amsterdam' },
  { city: 'Paris', region: 'Ile-de-France', country: 'France', countryCode: 'FR', lat: 48.8566, lon: 2.3522, timezone: 'Europe/Paris' },
  { city: 'Dublin', region: 'Leinster', country: 'Ireland', countryCode: 'IE', lat: 53.3498, lon: -6.2603, timezone: 'Europe/Dublin' },
  { city: 'Stockholm', region: 'Stockholm', country: 'Sweden', countryCode: 'SE', lat: 59.3293, lon: 18.0686, timezone: 'Europe/Stockholm' },
  { city: 'Zurich', region: 'Zurich', country: 'Switzerland', countryCode: 'CH', lat: 47.3769, lon: 8.5417, timezone: 'Europe/Zurich' },
  { city: 'Berlin', region: 'Berlin', country: 'Germany', countryCode: 'DE', lat: 52.5200, lon: 13.4050, timezone: 'Europe/Berlin' },
  { city: 'Munich', region: 'Bavaria', country: 'Germany', countryCode: 'DE', lat: 48.1351, lon: 11.5820, timezone: 'Europe/Berlin' },
  { city: 'Madrid', region: 'Madrid', country: 'Spain', countryCode: 'ES', lat: 40.4168, lon: -3.7038, timezone: 'Europe/Madrid' },
  { city: 'Barcelona', region: 'Catalonia', country: 'Spain', countryCode: 'ES', lat: 41.3851, lon: 2.1734, timezone: 'Europe/Madrid' },
  { city: 'Milan', region: 'Lombardy', country: 'Italy', countryCode: 'IT', lat: 45.4642, lon: 9.1900, timezone: 'Europe/Rome' },
  { city: 'Rome', region: 'Lazio', country: 'Italy', countryCode: 'IT', lat: 41.9028, lon: 12.4964, timezone: 'Europe/Rome' },
  { city: 'Vienna', region: 'Vienna', country: 'Austria', countryCode: 'AT', lat: 48.2082, lon: 16.3738, timezone: 'Europe/Vienna' },
  { city: 'Brussels', region: 'Brussels', country: 'Belgium', countryCode: 'BE', lat: 50.8503, lon: 4.3517, timezone: 'Europe/Brussels' },
  { city: 'Warsaw', region: 'Masovia', country: 'Poland', countryCode: 'PL', lat: 52.2297, lon: 21.0122, timezone: 'Europe/Warsaw' },
  { city: 'Prague', region: 'Prague', country: 'Czech Republic', countryCode: 'CZ', lat: 50.0755, lon: 14.4378, timezone: 'Europe/Prague' },
  { city: 'Copenhagen', region: 'Capital Region', country: 'Denmark', countryCode: 'DK', lat: 55.6761, lon: 12.5683, timezone: 'Europe/Copenhagen' },
  { city: 'Helsinki', region: 'Uusimaa', country: 'Finland', countryCode: 'FI', lat: 60.1699, lon: 24.9384, timezone: 'Europe/Helsinki' },
  { city: 'Oslo', region: 'Oslo', country: 'Norway', countryCode: 'NO', lat: 59.9139, lon: 10.7522, timezone: 'Europe/Oslo' },
  { city: 'Lisbon', region: 'Lisbon', country: 'Portugal', countryCode: 'PT', lat: 38.7223, lon: -9.1393, timezone: 'Europe/Lisbon' },
  { city: 'Bucharest', region: 'Bucharest', country: 'Romania', countryCode: 'RO', lat: 44.4268, lon: 26.1025, timezone: 'Europe/Bucharest' },
  { city: 'Moscow', region: 'Moscow', country: 'Russia', countryCode: 'RU', lat: 55.7558, lon: 37.6173, timezone: 'Europe/Moscow' },
  { city: 'Edinburgh', region: 'Scotland', country: 'United Kingdom', countryCode: 'GB', lat: 55.9533, lon: -3.1883, timezone: 'Europe/London' },
  { city: 'Manchester', region: 'England', country: 'United Kingdom', countryCode: 'GB', lat: 53.4808, lon: -2.2426, timezone: 'Europe/London' },
  // Asia (20)
  { city: 'Tokyo', region: 'Tokyo', country: 'Japan', countryCode: 'JP', lat: 35.6762, lon: 139.6503, timezone: 'Asia/Tokyo' },
  { city: 'Singapore', region: 'Singapore', country: 'Singapore', countryCode: 'SG', lat: 1.3521, lon: 103.8198, timezone: 'Asia/Singapore' },
  { city: 'Mumbai', region: 'Maharashtra', country: 'India', countryCode: 'IN', lat: 19.0760, lon: 72.8777, timezone: 'Asia/Kolkata' },
  { city: 'Seoul', region: 'Seoul', country: 'South Korea', countryCode: 'KR', lat: 37.5665, lon: 126.9780, timezone: 'Asia/Seoul' },
  { city: 'Hong Kong', region: 'Hong Kong', country: 'Hong Kong', countryCode: 'HK', lat: 22.3193, lon: 114.1694, timezone: 'Asia/Hong_Kong' },
  { city: 'Shanghai', region: 'Shanghai', country: 'China', countryCode: 'CN', lat: 31.2304, lon: 121.4737, timezone: 'Asia/Shanghai' },
  { city: 'Beijing', region: 'Beijing', country: 'China', countryCode: 'CN', lat: 39.9042, lon: 116.4074, timezone: 'Asia/Shanghai' },
  { city: 'Bangalore', region: 'Karnataka', country: 'India', countryCode: 'IN', lat: 12.9716, lon: 77.5946, timezone: 'Asia/Kolkata' },
  { city: 'Delhi', region: 'Delhi', country: 'India', countryCode: 'IN', lat: 28.7041, lon: 77.1025, timezone: 'Asia/Kolkata' },
  { city: 'Osaka', region: 'Osaka', country: 'Japan', countryCode: 'JP', lat: 34.6937, lon: 135.5023, timezone: 'Asia/Tokyo' },
  { city: 'Jakarta', region: 'Jakarta', country: 'Indonesia', countryCode: 'ID', lat: -6.2088, lon: 106.8456, timezone: 'Asia/Jakarta' },
  { city: 'Bangkok', region: 'Bangkok', country: 'Thailand', countryCode: 'TH', lat: 13.7563, lon: 100.5018, timezone: 'Asia/Bangkok' },
  { city: 'Taipei', region: 'Taiwan', country: 'Taiwan', countryCode: 'TW', lat: 25.0330, lon: 121.5654, timezone: 'Asia/Taipei' },
  { city: 'Kuala Lumpur', region: 'Federal Territory', country: 'Malaysia', countryCode: 'MY', lat: 3.1390, lon: 101.6869, timezone: 'Asia/Kuala_Lumpur' },
  { city: 'Manila', region: 'Metro Manila', country: 'Philippines', countryCode: 'PH', lat: 14.5995, lon: 120.9842, timezone: 'Asia/Manila' },
  { city: 'Hanoi', region: 'Hanoi', country: 'Vietnam', countryCode: 'VN', lat: 21.0278, lon: 105.8342, timezone: 'Asia/Ho_Chi_Minh' },
  { city: 'Ho Chi Minh City', region: 'Ho Chi Minh', country: 'Vietnam', countryCode: 'VN', lat: 10.8231, lon: 106.6297, timezone: 'Asia/Ho_Chi_Minh' },
  { city: 'Karachi', region: 'Sindh', country: 'Pakistan', countryCode: 'PK', lat: 24.8607, lon: 67.0011, timezone: 'Asia/Karachi' },
  { city: 'Hyderabad', region: 'Telangana', country: 'India', countryCode: 'IN', lat: 17.3850, lon: 78.4867, timezone: 'Asia/Kolkata' },
  { city: 'Chennai', region: 'Tamil Nadu', country: 'India', countryCode: 'IN', lat: 13.0827, lon: 80.2707, timezone: 'Asia/Kolkata' },
  // Middle East (8)
  { city: 'Dubai', region: 'Dubai', country: 'United Arab Emirates', countryCode: 'AE', lat: 25.2048, lon: 55.2708, timezone: 'Asia/Dubai' },
  { city: 'Tel Aviv', region: 'Tel Aviv', country: 'Israel', countryCode: 'IL', lat: 32.0853, lon: 34.7818, timezone: 'Asia/Jerusalem' },
  { city: 'Riyadh', region: 'Riyadh', country: 'Saudi Arabia', countryCode: 'SA', lat: 24.7136, lon: 46.6753, timezone: 'Asia/Riyadh' },
  { city: 'Istanbul', region: 'Istanbul', country: 'Turkey', countryCode: 'TR', lat: 41.0082, lon: 28.9784, timezone: 'Europe/Istanbul' },
  { city: 'Doha', region: 'Doha', country: 'Qatar', countryCode: 'QA', lat: 25.2854, lon: 51.5310, timezone: 'Asia/Qatar' },
  { city: 'Abu Dhabi', region: 'Abu Dhabi', country: 'United Arab Emirates', countryCode: 'AE', lat: 24.4539, lon: 54.3773, timezone: 'Asia/Dubai' },
  { city: 'Amman', region: 'Amman', country: 'Jordan', countryCode: 'JO', lat: 31.9454, lon: 35.9284, timezone: 'Asia/Amman' },
  { city: 'Muscat', region: 'Muscat', country: 'Oman', countryCode: 'OM', lat: 23.5880, lon: 58.3829, timezone: 'Asia/Muscat' },
  // South America (7)
  { city: 'Sao Paulo', region: 'Sao Paulo', country: 'Brazil', countryCode: 'BR', lat: -23.5505, lon: -46.6333, timezone: 'America/Sao_Paulo' },
  { city: 'Buenos Aires', region: 'Buenos Aires', country: 'Argentina', countryCode: 'AR', lat: -34.6037, lon: -58.3816, timezone: 'America/Argentina/Buenos_Aires' },
  { city: 'Santiago', region: 'Santiago', country: 'Chile', countryCode: 'CL', lat: -33.4489, lon: -70.6693, timezone: 'America/Santiago' },
  { city: 'Bogota', region: 'Bogota', country: 'Colombia', countryCode: 'CO', lat: 4.7110, lon: -74.0721, timezone: 'America/Bogota' },
  { city: 'Lima', region: 'Lima', country: 'Peru', countryCode: 'PE', lat: -12.0464, lon: -77.0428, timezone: 'America/Lima' },
  { city: 'Mexico City', region: 'Mexico City', country: 'Mexico', countryCode: 'MX', lat: 19.4326, lon: -99.1332, timezone: 'America/Mexico_City' },
  { city: 'Rio de Janeiro', region: 'Rio de Janeiro', country: 'Brazil', countryCode: 'BR', lat: -22.9068, lon: -43.1729, timezone: 'America/Sao_Paulo' },
  // Africa (7)
  { city: 'Lagos', region: 'Lagos', country: 'Nigeria', countryCode: 'NG', lat: 6.5244, lon: 3.3792, timezone: 'Africa/Lagos' },
  { city: 'Johannesburg', region: 'Gauteng', country: 'South Africa', countryCode: 'ZA', lat: -26.2041, lon: 28.0473, timezone: 'Africa/Johannesburg' },
  { city: 'Cairo', region: 'Cairo', country: 'Egypt', countryCode: 'EG', lat: 30.0444, lon: 31.2357, timezone: 'Africa/Cairo' },
  { city: 'Nairobi', region: 'Nairobi', country: 'Kenya', countryCode: 'KE', lat: -1.2921, lon: 36.8219, timezone: 'Africa/Nairobi' },
  { city: 'Cape Town', region: 'Western Cape', country: 'South Africa', countryCode: 'ZA', lat: -33.9249, lon: 18.4241, timezone: 'Africa/Johannesburg' },
  { city: 'Casablanca', region: 'Casablanca-Settat', country: 'Morocco', countryCode: 'MA', lat: 33.5731, lon: -7.5898, timezone: 'Africa/Casablanca' },
  { city: 'Accra', region: 'Greater Accra', country: 'Ghana', countryCode: 'GH', lat: 5.6037, lon: -0.1870, timezone: 'Africa/Accra' },
  // Oceania (5)
  { city: 'Sydney', region: 'New South Wales', country: 'Australia', countryCode: 'AU', lat: -33.8688, lon: 151.2093, timezone: 'Australia/Sydney' },
  { city: 'Melbourne', region: 'Victoria', country: 'Australia', countryCode: 'AU', lat: -37.8136, lon: 144.9631, timezone: 'Australia/Melbourne' },
  { city: 'Auckland', region: 'Auckland', country: 'New Zealand', countryCode: 'NZ', lat: -36.8485, lon: 174.7633, timezone: 'Pacific/Auckland' },
  { city: 'Brisbane', region: 'Queensland', country: 'Australia', countryCode: 'AU', lat: -27.4698, lon: 153.0251, timezone: 'Australia/Brisbane' },
  { city: 'Perth', region: 'Western Australia', country: 'Australia', countryCode: 'AU', lat: -31.9505, lon: 115.8605, timezone: 'Australia/Perth' },
];

// Hash-based IP-to-city mapping for better distribution across the full CITIES pool.
// Uses all four octets so that different IPs with the same first octet map to different cities.
function hashIPToIndex(ip) {
  const parts = ip.split('.').map(Number);
  // FNV-1a inspired hash over all four octets
  let h = 2166136261 >>> 0;
  for (let i = 0; i < parts.length; i++) {
    h ^= parts[i];
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h % CITIES.length;
}

function randomGeoIP(ip, seed) {
  if (ip) {
    const idx = hashIPToIndex(ip);
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
  const idx = hashIPToIndex(ip);
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
