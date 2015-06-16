var crypto = require("crypto");
// load common module
exports = module.exports = require('./cs1a.js');

// try compiled ecc, fall back to pure js one
try {
  if(process.env.PURE == 'true') throw new Error("pure requested");
  var ecc = require("ecc");
  // this validates that the compiled ecc can actually generate this curve
  new ecc.ECKey(ecc.ECCurves.secp160r1);
}catch(E){
  var ecc = require("ecc-jsbn");
}

// load node-specific crypto methods
exports.crypt(ecc, function(enc, key, iv, body)
{
  var aes = enc ? crypto.createCipheriv("AES-128-CTR", key, iv) : crypto.createDecipheriv("AES-128-CTR", key, iv);
  return Buffer.concat([aes.update(body), aes.final()]);
});
