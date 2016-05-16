var NodeCrypto = require("crypto");
var subtle = require("subtle")
  , pkcsPad1  = new Buffer([48, 130])
  , pkcsPad2  = new Buffer([2, 1, 0, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 4, 130])

function pkcs8_pad(privateBytes){
  var off1 = new Buffer([Math.floor(privateBytes.length / 256),((privateBytes.length + 22) % 256) ])
  var off2 = new Buffer([Math.floor(privateBytes.length / 256), (privateBytes.length % 256)])
  return Buffer.concat([pkcsPad1, off1, pkcsPad2, off2, privateBytes]);
}

function pkcs8_unpad(privateBytes){
  return privateBytes.slice(pkcsPad1.length + pkcsPad2.length + 4);
}

function Bufferize(arraybuffer){
  return new Buffer(new Uint8Array(arraybuffer))
}

exports.id = '2a';

// env-specific crypto methods
var forge;
var cecc;
exports.crypt = function(ecc,f)
{
  cecc = ecc;
  forge = f;
}
var rsa_alg = {
  name: "RSA-OAEP"
  , hash: {name: "SHA-256"}
  , modulusLength:2048
  , publicExponent : new Uint8Array([0x01,0x00,0x01])
};
exports.generate = function(){

  var usage = ["encrypt","decrypt"];
  var extractable = true;
  return subtle.generateKey(rsa_alg, extractable, usage)
        .then(function(pair){
          return Promise.all([
              subtle.exportKey("pkcs8",pair.privateKey)
              , subtle.exportKey("spki",pair.publicKey)
            ]);
        }).then(function(jwks){
          return {
            key: Bufferize(jwks[1])
            , secret : Bufferize(jwks[0])
          };
        });
}


exports.loadkey = function(id, key, secret){
  var alg = {}, importer;
  function privateHandler(privates){
    var oaep = privates[0]
      , ssa  = privates[1];

    id.sign = function cs2a_sign(buf){
      return subtle.sign({name: "RSASSA-PKCS1-v1_5"}, ssa, buf)
                   .then(Bufferize).catch(function(e){console.log("sign err",e)});
    }
    id.decrypt = function cs2a_decrypt(buf){
      return subtle.decrypt({name: "RSA-OAEP",hash:{name:"SHA-1"}}, oaep, buf)
                   .then(Bufferize).catch(function(e){console.log("decrypt err",e.stack)});
    }
  }

  function publicHandler(publics){
    var oaep = publics[0]
      , ssa  = publics[1];

    id.encrypt = function cs2a_encrypt(buf){
      return subtle.encrypt({name: "RSA-OAEP"}, oaep, buf)
                   .then(Bufferize).catch(function(e){console.log("encrypt err",e)});
    }
    id.verify = function cs2a_verify(a,b){
      return subtle.verify({name: "RSASSA-PKCS1-v1_5"}, ssa, b, a)
      .catch(function(e){
        console.log("verify err",e)
      })
    }
    return id;
  }

  function secret_import(secret){
    return Promise.all([ subtle.importKey("pkcs8", secret, {name: "RSA-OAEP", hash: {name: "SHA-1"}}, false, ["decrypt"])
                        , subtle.importKey("pkcs8", secret, {name: "RSASSA-PKCS1-v1_5", hash: {name: "SHA-256"}}, false, ["sign"])]);
  }

  function public_import(){
    return Promise.all([ subtle.importKey("spki", key, {name: "RSA-OAEP", hash: {name: "SHA-1"}}, false, ["encrypt"])
                       , subtle.importKey("spki", key, {name: "RSASSA-PKCS1-v1_5", hash: {name: "SHA-256"}}, false, ["verify"])]);
  }

  secret = (secret) ? pkcs8_pad(secret) : null;
  secret = (secret) ? secret_import(secret).then(privateHandler) : Promise.resolve();

  return secret.then(public_import).then(publicHandler);
}

exports.Local = function(pair){
  var self = this;

  self.key = {};
  this.load = (!(pair && pair.key && pair.secret)) ? Promise.reject(new Error("must supply valid keypair"))
                                                   : exports.loadkey(self.key,pair.key, pair.secret);


  self.decrypt = function cs2a_local_decrypt(body){
    return self.load.then(function cs2a_local_loaded_decrypt(){
      return (!Buffer.isBuffer(body))      ? Promise.reject(new Error("Message body must be a Buffer"))
           : (body.length < 256+12+256+16) ? Promise.reject(new Error("Message body below minimum length for valid encrypted cs2a packet"))
           : aes_unpack(body);
    }).then(aes_decrypt)
  };

  function aes_unpack(body){
    var keyBytes = body.slice(0,256)
    return self.key.decrypt(keyBytes)
                   .then(function(keys){
                     if(!keys || keys.length != (65+32))
                       throw new Error("failed to decrypt the aes keys")

                     return {
                       name      : "AES-GCM",
                       tagLength : 128,
                       iv        : body.slice(256,256 + 12),
                       additionalData : body.slice(0,256),
                       raw    : keys.slice(65, 65 + 32),
                       _keys  : keys,
                       body   : body.slice(256 + 12)
                     };
                   });
  }

  function aes_decrypt(alg){
    return subtle.importKey("raw",alg.raw, {name: "AES-GCM"},false,["encrypt","decrypt"])
          .then(function(key){
            return subtle.decrypt(alg, key, alg.body)
          })
          .then(function(body){
            var ret = body.slice(0, body.length - 256);
            ret._sig = body.slice(body.length - 256);
            ret._keys = alg._keys;
            return ret;
          })
  }
  return this;
}


function cs2a_load_remote(self, publicKey){
  return  exports.loadkey(self.key, publicKey)
                 .then(function(){
                   return subtle.generateKey({name : "ECDH", namedCurve: "P-256"},true, ["deriveBits"]);
                 })
                 .then(function (ecdhkeys){
                   self.ephemeral = ecdhkeys;
                   return subtle.exportKey("spki", ecdhkeys.publicKey)

                 })
                 .then(function (eccpub){
                   return self.key.encrypt(Buffer.concat([eccpub.slice(eccpub.length - 65), self.secret]));
                 })
                 .then(function (keyBytes){
                   self.keys = keyBytes;
                   self.token = NodeCrypto.createHash('sha256').update(keyBytes.slice(0,16)).digest().slice(0,16);
                   return subtle.importKey("raw", self.secret,{name:"AES-GCM",tagLength:128}, false,["encrypt","decrypt"])
                 });
}

exports.Remote = function(publicKey)
{
  this.key = {};
  this.secret = NodeCrypto.randomBytes(32);
  this.load = cs2a_load_remote(this, publicKey);
  var self = this;
  var iv   = NodeCrypto.randomBytes(12);

  this.verify = function(local, body){
    // decrypt it first
    var cached;
    return self.load.then(function cs2a_remote_verify(){
      return local.decrypt(body);
    }).then(function(inner){
      var toVerify = Buffer.concat([body.slice(0,256+12),inner])
      cached = inner._keys;
      return self.key.verify( toVerify, inner._sig)
    })
    .then(function(verified){
      if (verified)
        self.cached = cached;
      return verified;
    });
  };

  this.encrypt = function(local, inner){
    var seq = iv.readUInt32LE(0)
      , aesKey;

    iv.writeUInt32LE(++seq,0);

    // generate the signature
    return self.load.then(function cs2a_remote_encrypt1(aes){
      aesKey = aes;
      return local.key.sign(Buffer.concat([self.keys,iv,inner]));
    }).then(function cs2a_remote_encrypt2(sig){
      var body = Buffer.concat([inner, sig]);
      return subtle.encrypt({name: "AES-GCM", tagLength:128,iv:iv, additionalData : self.keys}, aesKey, body);
    }).then(function cs2a_remote_encrypt3(encrypted){
      return Buffer.concat([self.keys,iv,encrypted]);
    });
  };
}

var spkiECCPad = new Buffer("3056301006042b81047006082a8648ce3d030107034200","hex")

function cs2a_load_ephemeral(remote, keys){
  var aesBytes = keys.slice(65)
    , eccBytes = keys.slice(0, 65)
    , eccSPKI  = Buffer.concat([spkiECCPad,eccBytes]);

  return subtle.importKey("spki", eccSPKI, {name:"ECDH",namedCurve:"P-256"},true,[])
        .then(function(key){
          return subtle.deriveBits({name:"ECDH", namedCurve:"P-256", public: key}, remote.ephemeral.privateKey,256)
        })
        .then(function(ecdhe){
          var encBytes = Buffer.concat([ecdhe, remote.secret,keys.slice(65)])
            , decBytes = Buffer.concat([ecdhe, keys.slice(65),remote.secret]);

          return Promise.all([ subtle.digest({name:"SHA-256"}, encBytes)
                             , subtle.digest({name:"SHA-256"}, decBytes) ]);
        })
        .then(function(secrets){
          var encBytes = secrets[0]
            , decBytes = secrets[1];

          return Promise.all([ subtle.importKey("raw", encBytes,{name:"AES-GCM"},false, ["encrypt"])
                             , subtle.importKey("raw", decBytes,{name:"AES-GCM"},false, ["decrypt"]) ]);
        })
        .then(function(cryptoKeys){
          return {
            encKey : cryptoKeys[0],
            decKey : cryptoKeys[1]
          };
        })
}

exports.Ephemeral = function(remote, outer, inner){
  var keys = remote.cached || (inner._keys)
    , self = this
    , iv   = NodeCrypto.randomBytes(12);

  this.load = cs2a_load_ephemeral(remote, keys);
  this.token = NodeCrypto.createHash('sha256').update(outer.slice(0,16)).digest().slice(0,16);


  this.encrypt = function cs2a_ephemeral_encrypt(inner){
    // incriment the iv
    var seq = iv.readUInt32LE(0);
    iv.writeUInt32LE(++seq,0);

    return self.load.then(function cs2a_ephemeral_encrypt1(keys){
      return subtle.encrypt({name: "AES-GCM", iv:iv, additionalData: new Buffer(0), tagLength: 128}, keys.encKey, inner)
    }).then(function(cbody){
      //attach the iv
      return Buffer.concat([iv, cbody]);
    });
  };

  this.decrypt = function cs2a_ephemeral_decrypt(outer){
    return self.load.then(function cs2a_ephemeral_decrypt1(keys){
      return subtle.decrypt({ name: "AES-GCM", iv:outer.slice(0,12), additionalData: new Buffer(0), tagLength: 128}
                            , keys.decKey
                            , outer.slice(12));
    });
  };

  return this;
}
