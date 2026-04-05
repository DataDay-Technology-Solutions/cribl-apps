#!/usr/bin/env node
'use strict';

/**
 * fix-index.js — Rebuilds src/definitions/index.js from all JSON definition files.
 */

const fs = require('fs');
const path = require('path');

const dir = path.join(__dirname, '..', 'src', 'definitions');
const indexFile = path.join(dir, 'index.js');

// Read all JSON files and extract sourcetypes
const files = fs.readdirSync(dir).filter(f => f.endsWith('.json')).sort();
const entries = [];

for (const file of files) {
  try {
    const raw = fs.readFileSync(path.join(dir, file), 'utf8');
    const def = JSON.parse(raw);
    if (def.sourcetype) {
      const st = def.sourcetype;
      const slug = file.replace('.json', '');
      entries.push([st, file]);
      if (slug !== st) {
        entries.push([slug, file]);
      }
    }
  } catch (e) { /* skip */ }
}

// Sort entries for clean output
entries.sort((a, b) => a[0].localeCompare(b[0]));

// Read existing index.js to preserve the functions section
const indexContent = fs.readFileSync(indexFile, 'utf8');
const fnStart = indexContent.indexOf('const DEFINITIONS_DIR');
const functionsSection = indexContent.slice(fnStart);

// Build new map lines
const mapLines = entries.map(([st, file]) => {
  const key = "'" + st + "'";
  return '  ' + key.padEnd(40) + ": '" + file + "',";
});

const newIndex = `'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Sourcetype-to-filename mapping.
 * Maps sourcetype identifiers used in scenarios/CLI to their
 * corresponding definition JSON files on disk.
 * Auto-generated: ${files.length} definitions, ${entries.length} map entries.
 */
const SOURCETYPE_MAP = {
${mapLines.join('\n')}
};

${functionsSection}`;

fs.writeFileSync(indexFile, newIndex, 'utf8');
console.log(`Rebuilt index.js with ${entries.length} map entries from ${files.length} files`);
