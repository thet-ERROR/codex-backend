// --- 🎨 THEMES ---
// Six full looks for the site replace the thirteen accent colours of before (Nov 2026). Three are free
// (Graphite, the clean matte one, is the default), one comes from the wheel, one from a rank, one is the Konami secret.
//
// Nothing stored is rewritten: accounts keep their old `unlockedColors` exactly as they are, and the
// themes they open are worked out from them on every read (themesFor). So nobody loses what they won,
// and a rollback of this file loses nothing either. New wins are stored in `unlockedThemes`.

const THEMES = ['graphite', 'phoenix', 'nebula', 'inferno', 'arctic', 'phantom'];
const FREE_THEMES = ['graphite', 'phoenix', 'nebula'];

// Every colour an account could have won before, and the theme it now opens. Note that the old rank
// colour called 'phantom' opens Arctic (the rank theme); the Phantom theme is the Konami one, which was
// the colour 'cheatCode'.
const THEME_OF_COLOR = {
    cyberGold: 'inferno', toxicOrange: 'inferno', neonPink: 'inferno', matrixGreen: 'inferno', // wheel
    ultraviolet: 'arctic', arctic: 'arctic', phantom: 'arctic',                                   // ranks
    cheatCode: 'phantom'                                                                          // Konami
};

// The themes an account can wear, in the order the settings show them
function themesFor(user) {
    const have = new Set(FREE_THEMES);
    for (const t of user.unlockedThemes || []) if (THEMES.includes(t)) have.add(t);
    for (const c of user.unlockedColors || []) if (THEME_OF_COLOR[c]) have.add(THEME_OF_COLOR[c]);
    return THEMES.filter(t => have.has(t));
}

// Stores a theme won just now (on the document; the caller saves). Returns false when the account
// could already wear it, from either list, so the caller can say "already yours".
function grantTheme(user, theme) {
    if (themesFor(user).includes(theme)) return false;
    if (!user.unlockedThemes) user.unlockedThemes = [];
    user.unlockedThemes.push(theme);
    return true;
}

module.exports = { THEMES, FREE_THEMES, THEME_OF_COLOR, themesFor, grantTheme };
