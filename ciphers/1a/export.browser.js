var crypto = require("crypto");
var cs1a = require("./cs1a.js");

var ecc = require("ecc-jsbn");
require("../forge/forge.min.js"); // PITA not browserify compat
cs1a.crypt(ecc,function(enc, key, iv, body)
{
	var cipher = enc ? forge.aes.createEncryptionCipher(key.toString("binary"), "CTR") : forge.aes.createDecryptionCipher(key.toString("binary"), "CTR");
	cipher.start(iv.toString("binary"));
	cipher.update(forge.util.createBuffer(body.toString('binary')));
	cipher.finish();
  return new Buffer(cipher.output.getBytes(), "binary");
});

Object.keys(cs1a).forEach(function(f){ exports[f] = cs1a[f]; });
