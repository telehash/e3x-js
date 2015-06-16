// load common module
exports = module.exports = require('./cs2a.js');

var ecc = require("ecc-jsbn");
require("../forge/forge.min.js"); // PITA not browserify compat

// load browser-specific crypto methods
exports.crypt(ecc,forge);
