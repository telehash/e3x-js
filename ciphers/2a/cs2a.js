var crypto = require("crypto");
var sjcl = require("sjcl");

exports.id = '2a';

// env-specific crypto methods
var forge;
var cecc;
exports.crypt = function(ecc,f)
{
  cecc = ecc;
  forge = f;
}

exports.generate = function(cb)
{
  // disable web-workers for now, not browserify compatible
//  forge.rsa.generateKeyPair({bits: 2048, e: 0x10001, workers: -1}, function(err, keys){
  var keys = forge.rsa.generateKeyPair({bits: 2048, e: 0x10001});
  if(!keys) return cb("failed to generate rsa keys");
  var key = forge.asn1.toDer(forge.pki.publicKeyToAsn1(keys.publicKey)).bytes();
  var secret = forge.asn1.toDer(forge.pki.privateKeyToAsn1(keys.privateKey)).bytes();
  cb(null, {key:new Buffer(key, 'binary'), secret:new Buffer(secret, 'binary')});
}

exports.loadkey = function(id, key, secret)
{
  var pk = forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(key.toString("binary")));
  id.encrypt = function(buf){
    return new Buffer(pk.encrypt(buf.toString("binary"), "RSA-OAEP"), "binary");
  };
  id.verify = function(a,b){
    var md = forge.md.sha256.create();
    md.update(a.toString("binary"));
    return pk.verify(md.digest().bytes(), b.toString("binary"));
  };
  if(secret)
  {
    var sk = forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(secret.toString("binary")));
    id.sign = function(buf){
      var md = forge.md.sha256.create();
      md.update(buf.toString("binary"));
      return new Buffer(sk.sign(md),"binary");
    };
    id.decrypt = function(buf){
      return new Buffer(sk.decrypt(buf.toString("binary"), "RSA-OAEP"),"binary");
    };
  }
  return undefined;
}

exports.Local = function(pair)
{
  var self = this;
  self.key = {}
  try{
    self.err = exports.loadkey(self.key,pair.key,pair.secret);
  }catch(E){
    self.err = E;
  }

  // decrypt message body and return the inner
  self.decrypt = function(body){
    if(!Buffer.isBuffer(body)) return false;
    if(body.length < 256+12+256+16) return false;

    // rsa decrypt the keys
    var keys = self.key.decrypt(body.slice(0,256));
    if(!keys || keys.length != (65+32)) return false;
    // aes decrypt the inner
    var keyhex = keys.slice(65,65+32).toString('hex');
    var ivhex = body.slice(256,256+12).toString('hex');
    var aadhex = body.slice(0,256).toString('hex');
    var cbodyhex = body.slice(256+12).toString('hex');

    var key = new sjcl.cipher.aes(sjcl.codec.hex.toBits(keyhex));
    var iv = sjcl.codec.hex.toBits(ivhex);
    var aad = sjcl.codec.hex.toBits(aadhex);
    var cbody = sjcl.codec.hex.toBits(cbodyhex);
    var cipher = sjcl.mode.gcm.decrypt(key, cbody, iv, aad, 128);
    var body = new Buffer(sjcl.codec.hex.fromBits(cipher), 'hex');

    // return buf of just the inner, add decrypted sig/keys
    var ret = body.slice(0,body.length-256);
    ret._keys = keys;
    ret._sig = body.slice(ret.length);

    return ret;
  };
}

exports.Remote = function(key)
{
  var self = this;
  self.key = {};
  try{
    self.err = exports.loadkey(self.key,key);
    self.ephemeral = new cecc.ECKey(cecc.ECCurves.secp256r1);
    self.secret = crypto.randomBytes(32);
    self.iv = crypto.randomBytes(12);
    self.keys = self.key.encrypt(Buffer.concat([self.ephemeral.PublicKey,self.secret]));
    self.token = crypto.createHash('sha256').update(self.keys.slice(0,16)).digest().slice(0,16);
  }catch(E){
    self.err = E;
  }
  if(self.err) console.log("ERR",self.err,key.toString("hex"))

  // verifies the authenticity of an incoming message body
  self.verify = function(local, body){
    if(!Buffer.isBuffer(body)) return false;

    // decrypt it first
    var inner = local.decrypt(body);
    if(!inner) return false;

    // verify the rsa signature
    if(!self.key.verify(Buffer.concat([body.slice(0,256+12),inner]), inner._sig)) return false;

    // cache the decrypted keys
    self.cached = inner._keys;

    return true;
  };

  self.encrypt = function(local, inner){
    if(!Buffer.isBuffer(inner)) return false;

    // increment the IV
    var seq = self.iv.readUInt32LE(0);
    seq++;
    self.iv.writeUInt32LE(seq,0);

    // generate the signature
    var sig = local.key.sign(Buffer.concat([self.keys,self.iv,inner]));

    // aes gcm encrypt the inner+sig
    var aad = self.keys;
    var body = Buffer.concat([inner,sig]);
    var key = new sjcl.cipher.aes(sjcl.codec.hex.toBits(self.secret.toString('hex')));
    var iv = sjcl.codec.hex.toBits(self.iv.toString('hex'));
    var cipher = sjcl.mode.gcm.encrypt(key, sjcl.codec.hex.toBits(body.toString('hex')), iv, sjcl.codec.hex.toBits(aad.toString('hex')), 128);
    var cbody = new Buffer(sjcl.codec.hex.fromBits(cipher), 'hex');

    // all done!
    return Buffer.concat([self.keys,self.iv,cbody]);

  };

}

exports.Ephemeral = function(remote, outer, inner)
{
  var self = this;

  try {
    // get the ecc key from cached or decrypted
    var keys = remote.cached || (inner && inner._keys);

    // do the ecdh thing
    var ecc = new cecc.ECKey(cecc.ECCurves.secp256r1, keys.slice(0,65), true);
    var ecdhe = remote.ephemeral.deriveSharedSecret(ecc);

    // use the other two secrets too
    var secret = keys.slice(65);
    var hex = crypto.createHash("sha256")
      .update(ecdhe)
      .update(remote.secret)
      .update(secret)
      .digest("hex");
    self.encKey = new sjcl.cipher.aes(sjcl.codec.hex.toBits(hex));
    var hex = crypto.createHash("sha256")
      .update(ecdhe)
      .update(secret)
      .update(remote.secret)
      .digest("hex");
    self.decKey = new sjcl.cipher.aes(sjcl.codec.hex.toBits(hex));

    self.token = crypto.createHash('sha256').update(outer.slice(0,16)).digest().slice(0,16);

    self.iv = crypto.randomBytes(12);

  }catch(E){
    self.err = E;
  }


  self.decrypt = function(outer){

    try{
      var ivhex = sjcl.codec.hex.toBits(outer.slice(0,12).toString("hex"));
      var cipher = sjcl.mode.gcm.decrypt(self.decKey, sjcl.codec.hex.toBits(outer.slice(12).toString("hex")), ivhex, [], 128);
      var inner = new Buffer(sjcl.codec.hex.fromBits(cipher),"hex");
    }catch(E){
      self.err = E;
    }

    return inner;
  };

  self.encrypt = function(inner){

    // increment the IV
    var seq = self.iv.readUInt32LE(0);
    seq++;
    self.iv.writeUInt32LE(seq,0);

    // now encrypt the packet
    var cipher = sjcl.mode.gcm.encrypt(self.encKey, sjcl.codec.hex.toBits(inner.toString("hex")), sjcl.codec.hex.toBits(self.iv.toString("hex")), [], 128);
    var cbody = new Buffer(sjcl.codec.hex.fromBits(cipher),"hex");

    return Buffer.concat([self.iv,cbody]);
  };
}
