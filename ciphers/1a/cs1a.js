
var NodeCrypto = require('crypto');
var subtle = require("subtle")


var Subtle_Options = {
  HMAC: {
    name: "HMAC"
    , hash: {name: "SHA-256"}
    , usage: ["sign","verify"]
    , extractable : false
  }

                }
exports.id = '1a';

// env-specific crypto methods
exports.crypt = function(ecc,aes)
{
  NodeCrypto.ecc = ecc;
  NodeCrypto.aes = aes;
}

exports.generate = function(cb)
{

  try {
    var k = new NodeCrypto.ecc.ECKey(NodeCrypto.ecc.ECCurves.secp160r1);
  }catch(E){
    return cb(E);
  }
  cb(null, {key:k.PublicKey, secret:k.PrivateKey});
}

exports._Local = function(pair){
  var local = new exports.Local(pair)

  this.token = local.token
  this.decrypt = function(body){
    return Promise.resolve(local.decrypt(body))
  }

  return Promise.resolve(this)
}

exports._Remote = function(key){
  var remote = new exports.Remote(key)
  this.token = remote.token
  this.encrypt = function(a1, a2){
    return Promise.resolve(remote.encrypt(a1, a2))
  }

  this.verify  = remote._verify;

  return Promise.resolve(this)
}

exports._Ephemeral = function(remote, body){
  var ephemeral = new exports.Ephemeral(remote, body)
  this.token = ephemeral.token
  this.encrypt = function(body){
    return Promise.resolve(ephemeral.encrypt(body))
  }

  this.decrypt = function(body){
    return Promise.resolve(ephemeral.decrypt(body))
  }

  return Promise.resolve(this)
}

exports.Local = function(pair)
{
  var self = this;
  try{
    self.key = new NodeCrypto.ecc.ECKey(NodeCrypto.ecc.ECCurves.secp160r1, pair.key, true);
    self.secret = new NodeCrypto.ecc.ECKey(NodeCrypto.ecc.ECCurves.secp160r1, pair.secret);
    if(self.key.PublicKey.toString() != pair.key.toString()) throw new Error('invalid public key data');
    if(self.secret.PrivateKey.toString() != pair.secret.toString()) throw new Error('invalid secret key data');
  }catch(E){
    self.err = E;
  }

  // decrypt message body and return the inner
  self.decrypt = function(body){
    if(!Buffer.isBuffer(body)) return false;
    if(body.length < 21+4+4) return false;

    var keybuf = body.slice(0,21);
    var iv = body.slice(21,21+4);
    var innerc = body.slice(21+4,body.length-4);
    // mac is handled during verify stage

    try{
      var ephemeral = new NodeCrypto.ecc.ECKey(NodeCrypto.ecc.ECCurves.secp160r1, keybuf, true);
      var secret = self.secret.deriveSharedSecret(ephemeral);
    }catch(E){
      return false;
    }

    var key = fold(1,NodeCrypto.createHash("sha256").update(secret).digest());
    var ivz = new Buffer(12);
    ivz.fill(0);

    // aes-128 decipher the inner
    try{
      var inner = NodeCrypto.aes(false, key, Buffer.concat([iv,ivz]), innerc);
    }catch(E){
      return false;
    }

    return inner;
  };
}

exports.Remote = function(key)
{
  var self = this;
  try{
    self.endpoint = new NodeCrypto.ecc.ECKey(NodeCrypto.ecc.ECCurves.secp160r1, key, true);
    self.ephemeral = new NodeCrypto.ecc.ECKey(NodeCrypto.ecc.ECCurves.secp160r1);
    self.token = NodeCrypto.createHash('sha256').update(self.ephemeral.PublicKey.slice(0,16)).digest().slice(0,16);
    self.seq = NodeCrypto.randomBytes(4).readUInt32LE(0); // start from random place
  }catch(E){
    self.err = E;
  }

  self._verify = function(local, body){

      if(!Buffer.isBuffer(body))
        return Promise.reject(new Error("CS1a verify: 2nd argument not a Buffer"));

      // derive shared secret from both identity keys
      var secret = local.secret.deriveSharedSecret(self.endpoint);

      // hmac key is the secret and seq bytes combined to make it unique each time
      var iv = body.slice(21,21+4);
    return subtle.importKey("raw",Buffer.concat([secret,iv]),Subtle_Options.HMAC,  true, Subtle_Options.HMAC.usage)
          .then(function(key){
            console.log("HMAC KEY", key)
            return subtle.sign({name:"HMAC"}, key, body.slice(0,body.length-4))
          })
          .then(function(sig){
            var mac = fold(3,new Buffer(new Uint8Array(sig)));
            var passed = (mac.toString('hex') === body.slice(body.length-4).toString('hex'));
            return (passed) ? true : Promise.reject();
          })
  }

  // verifies the hmac on an incoming message body
  self.verify = function(local, body){
    if(!Buffer.isBuffer(body)) return false;

    // derive shared secret from both identity keys
    var secret = local.secret.deriveSharedSecret(self.endpoint);

    // hmac key is the secret and seq bytes combined to make it unique each time
    var iv = body.slice(21,21+4);
    var dig = NodeCrypto.createHmac("sha256", Buffer.concat([secret,iv])).update(body.slice(0,body.length-4)).digest();
    var mac = fold(3,dig)



    if(mac.toString('hex') != body.slice(body.length-4).toString('hex')) return false;

    return true;
  };

  self.encrypt = function(local, inner){
    if(!Buffer.isBuffer(inner)) return false;

    // get the shared secret to create the iv+key for the open aes
    try{
      var secret = self.ephemeral.deriveSharedSecret(self.endpoint);
    }catch(E){
      return false;
    }
    var key = fold(1,NodeCrypto.createHash("sha256").update(secret).digest());
    var iv = new Buffer(4);
    iv.writeUInt32LE(self.seq++,0);
    var ivz = new Buffer(12);
    ivz.fill(0);

    // encrypt the inner
    try{
      var innerc = NodeCrypto.aes(true, key, Buffer.concat([iv,ivz]), inner);
      var macsecret = local.secret.deriveSharedSecret(self.endpoint);
    }catch(E){
      return false;
    }

    // prepend the key and hmac it
    var macd = Buffer.concat([self.ephemeral.PublicKey,iv,innerc]);
    // key is the secret and seq bytes combined
    var hmac = fold(3,NodeCrypto.createHmac("sha256", Buffer.concat([macsecret,iv])).update(macd).digest());

    // create final message body
    return Buffer.concat([macd,hmac]);
  };

}

exports.Ephemeral = function(remote, body)
{
  var self = this;

  self.seq = NodeCrypto.randomBytes(4).readUInt32LE(0); // start from random place

  try{
    // sender token
    self.token = NodeCrypto.createHash('sha256').update(body.slice(0,16)).digest().slice(0,16);

    // extract received ephemeral key
    var key = new NodeCrypto.ecc.ECKey(NodeCrypto.ecc.ECCurves.secp160r1, body.slice(0,21), true);

    // get shared secret to make channel keys
    var secret = remote.ephemeral.deriveSharedSecret(key);
    self.encKey = fold(1,NodeCrypto.createHash("sha256")
      .update(secret)
      .update(remote.ephemeral.PublicKey)
      .update(key.PublicKey)
      .digest());
    self.decKey = fold(1,NodeCrypto.createHash("sha256")
      .update(secret)
      .update(key.PublicKey)
      .update(remote.ephemeral.PublicKey)
      .digest());
  }catch(E){
    self.err = E;
  }

  self.decrypt = function(outer){
    // extract the three buffers
    var seq = outer.slice(0,4);
    var cbody = outer.slice(4,outer.length-4);
    var mac1 = outer.slice(outer.length-4);

    // validate the hmac
    var key = Buffer.concat([self.decKey,seq]);
    var mac2 = fold(3,NodeCrypto.createHmac("sha256", key).update(cbody).digest());
    if(mac1.toString('hex') != mac2.toString('hex')) return false;

    // decrypt body
    var ivz = new Buffer(12);
    ivz.fill(0);
    try{
      var body = NodeCrypto.aes(false,self.decKey,Buffer.concat([seq,ivz]),cbody);
    }catch(E){
      return false;
    }
    return body;
  };

  self.encrypt = function(inner){
    // now encrypt the packet
    var iv = new Buffer(16);
    iv.fill(0);
    iv.writeUInt32LE(self.seq++,0);

    var cbody = NodeCrypto.aes(true, self.encKey, iv, inner);

    // create the hmac
    var key = Buffer.concat([self.encKey,iv.slice(0,4)]);
    var mac = fold(3,NodeCrypto.createHmac("sha256", key).update(cbody).digest());

    // return final body
    return Buffer.concat([iv.slice(0,4),cbody,mac]);
  };
}


// simple xor buffer folder
function fold(count, buf)
{
  if(!count || buf.length % 2) return buf;
  var ret = buf.slice(0,buf.length/2);
  for(var i = 0; i < ret.length; i++) ret[i] = ret[i] ^ buf[i+ret.length];
  return fold(count-1,ret);
}
