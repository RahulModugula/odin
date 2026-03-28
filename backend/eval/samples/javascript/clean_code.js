/**
 * Clean JavaScript module — should produce zero findings.
 * Demonstrates proper practices: const/let, no console.log,
 * sanitized HTML, proper error handling.
 */

const MAX_RETRIES = 3;
const TIMEOUT_MS = 5000;

/**
 * Fetch data from an API with retry logic.
 * @param {string} url - The endpoint URL
 * @param {number} retries - Number of retries remaining
 * @returns {Promise<object>} Parsed JSON response
 */
async function fetchWithRetry(url, retries = MAX_RETRIES) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const response = await fetch(url, {
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      return await response.json();
    } catch (err) {
      if (attempt === retries) {
        throw err;
      }
      await new Promise((resolve) => setTimeout(resolve, 1000 * attempt));
    }
  }
}

/**
 * Safely render user content as text (not HTML).
 * @param {HTMLElement} element - Target DOM element
 * @param {string} text - User-provided text content
 */
function renderUserContent(element, text) {
  element.textContent = text; // Safe: textContent, not innerHTML
}

/**
 * Deep merge objects with prototype pollution guard.
 * @param {object} target - Target object
 * @param {object} source - Source object
 * @returns {object} Merged result
 */
function safeMerge(target, source) {
  const result = { ...target };
  for (const key of Object.keys(source)) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      continue;
    }
    if (typeof source[key] === "object" && source[key] !== null) {
      result[key] = safeMerge(result[key] || {}, source[key]);
    } else {
      result[key] = source[key];
    }
  }
  return result;
}

export { fetchWithRetry, renderUserContent, safeMerge };
