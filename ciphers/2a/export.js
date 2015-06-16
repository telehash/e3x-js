var crypto = require("crypto");

// load common module
exports = module.exports = require('./cs2a.js');

// prefer compiled versions

try {
  if(process.env.PURE == 'true') throw new Error("pure requested");
  var ecc = require("ecc-qj");
}catch(E){
  console.log("ecc?", E)
  var ecc = require("ecc-jsbn")
}

var forge = require("node-forge");
try {
  if(process.env.PURE == 'true') throw new Error("pure requested");
  var ursa = require("ursa");
}catch(E){
  console.log("ursa?", E)
}

// load node-specific crypto methods
exports.crypt(ecc,forge);

// replace these when compiled ursa works and forge won't be used
if(ursa)
{
  exports.generate = function(cb)
  {
    var kpair = ursa.generatePrivateKey();
    var key = str2der(kpair.toPublicPem("utf8"));
    var secret = str2der(kpair.toPrivatePem("utf8"));
    cb(null,{key:key,secret:secret});
  }

  exports.loadkey = function(id, key, secret)
  {
    // TODO, figure out why ursa is rejecting valid pub keys, workaround is using forge
    var pkf = forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(key.toString("binary")));     var pem = forge.pki.publicKeyToPem(pkf);
    var pk = ursa.coercePublicKey(pem);
//    var pk = ursa.coercePublicKey(der2pem(key,"PUBLIC"));
    if(!pk) return true;
    if(pk.getModulus().length != 256) return true;
    id.encrypt = function(buf){
      return pk.encrypt(buf, undefined, undefined, ursa.RSA_PKCS1_OAEP_PADDING);
    };
    id.verify = function(a,b){
      return pk.hashAndVerify("sha256", a, b);
    };
    if(secret)
    {
      var sk = ursa.coercePrivateKey(der2pem(secret,"RSA PRIVATE"));
      id.sign = function(buf){
        return sk.hashAndSign("sha256", buf);
      };
      id.decrypt = function(buf){
        return sk.decrypt(buf, undefined, undefined, ursa.RSA_PKCS1_OAEP_PADDING);
      };
    }
    return undefined;
  }
}

// ursa is not very flexible!

var PEM_REGEX = /^(-----BEGIN (.*) KEY-----\r?\n([\/+=a-zA-Z0-9\r\n]*)\r?\n-----END \2 KEY-----\r?\n)/m;
function str2der(str)
{
  var r = PEM_REGEX.exec(str);
  var b64 = r ? r[3] : str;
  return new Buffer(b64, "base64");
}
function der2pem(der,type)
{
  if(!der || !Buffer.isBuffer(der)) return false;
  var b64 = der.toString("base64");
  if(!b64) return false;
  b64 = b64.match(/.{1,64}/g).join("\n");
  return "-----BEGIN "+type+" KEY-----\n"+b64+"\n-----END "+type+" KEY-----\n";
}
