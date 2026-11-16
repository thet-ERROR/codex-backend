// A PC's strong points: up to three short lines per language, written by the admin, shown by the
// storefront's assistant when it recommends the PC. The shop's own words in front of customers, so they are
// checked strictly and refused (not quietly cut) when they don't fit, so the admin sees what went wrong.
const MAX_LINES = 3;
const MAX_CHARS = 90;

// { value } with the cleaned lists, or { error }. Absent (undefined) is fine: nothing to change.
function cleanHighlights(input) {
    if (input === undefined) return { value: undefined };
    if (!input || typeof input !== 'object' || Array.isArray(input)) return { error: 'Strong points must be a list per language' };
    const value = {};
    for (const lang of ['el', 'en']) {
        const list = input[lang] === undefined ? [] : input[lang];
        if (!Array.isArray(list) || list.some(l => typeof l !== 'string')) return { error: 'Strong points must be a list of text per language' };
        const lines = list.map(l => l.trim()).filter(Boolean);
        if (lines.length > MAX_LINES) return { error: `At most ${MAX_LINES} strong points per language` };
        if (lines.some(l => l.length > MAX_CHARS)) return { error: `A strong point can be at most ${MAX_CHARS} characters` };
        if (lines.some(l => /[<>]/.test(l))) return { error: 'Strong points cannot contain < or >' };
        value[lang] = lines;
    }
    return { value };
}

module.exports = { cleanHighlights, MAX_LINES, MAX_CHARS };
