// Intentionally vulnerable: prototype pollution patterns. For eval only.

// Pattern 1: recursive merge without __proto__ guard
function deepMerge(target, source) {
    for (const key of Object.keys(source)) {
        // No check for __proto__, constructor, prototype
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            deepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Pattern 2: path-based property assignment — __proto__.isAdmin poisoning
function setConfig(obj, path, value) {
    const keys = path.split('.');
    let cur = obj;
    for (let i = 0; i < keys.length - 1; i++) {
        if (!cur[keys[i]]) cur[keys[i]] = {};
        cur = cur[keys[i]];
    }
    cur[keys[keys.length - 1]] = value;
}

// Dangerous usage: user controls the "path" parameter
const config = {};
setConfig(config, '__proto__.isAdmin', true);
console.log({}.isAdmin); // true
