'use strict';

/**
 * Scenario Registry
 *
 * Loads all scenario modules and exposes a simple lookup API.
 * Each scenario is a plain object describing actors, phases, and the
 * event templates that the correlation engine uses to generate
 * production-realistic streaming data.
 */

const scenarios = {
  'brute-force': require('./brute-force'),
  'normal-day': require('./normal-day'),
  'data-exfil': require('./data-exfil'),
  'insider-threat': require('./insider-threat'),
};

/**
 * Retrieve a scenario by name.
 * @param {string} name - Scenario identifier (e.g. 'brute-force')
 * @returns {Object} The scenario definition
 * @throws {Error} If the requested scenario does not exist
 */
function getScenario(name) {
  const scenario = scenarios[name];
  if (!scenario) {
    const available = Object.keys(scenarios).join(', ');
    throw new Error(`Unknown scenario "${name}". Available scenarios: ${available}`);
  }
  return scenario;
}

/**
 * List all registered scenarios with name and description.
 * @returns {Array<{name: string, description: string, phaseCount: number}>}
 */
function listScenarios() {
  return Object.values(scenarios).map((s) => ({
    name: s.name,
    description: s.description,
    phaseCount: s.phases.length,
  }));
}

/**
 * Get the names of all registered scenarios.
 * @returns {string[]}
 */
function getScenarioNames() {
  return Object.keys(scenarios);
}

module.exports = {
  scenarios,
  getScenario,
  listScenarios,
  getScenarioNames,
};
