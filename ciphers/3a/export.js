
// load common module
exports = module.exports = require('./cs3a.js');

// try compiled sodium, fall back to pure js one (TODO)
try{
  if(process.env.PURE == 'true') throw new Error("pure requested");
  var sodium = require("sodium").api;
  // load node-specific crypto methods
  exports.crypt(sodium);
}catch(E){
  var browser = require('./export.browser.js');
  exports.crypt(browser.sodium());
}
