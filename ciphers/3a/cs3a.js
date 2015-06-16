var crypto = require('crypto');
var sodium = {};

exports.id = '3a';

// env-specific crypto methods
exports.crypt = function(lib)
{
  sodium = lib;
}

exports.generate = function(cb)
{
  var kp = sodium.crypto_box_keypair();
  cb(null, {key:kp.publicKey, secret:kp.secretKey});
}

exports.Local = function(pair)
{
  var self = this;
  try{
    if(!Buffer.isBuffer(pair.key) || pair.key.length != 32) throw new Error("invalid public key");
    self.key = pair.key;
    if(!Buffer.isBuffer(pair.secret) || pair.secret.length != 32) throw new Error("invalid secret key");
    self.secret = pair.secret;
  }catch(E){
    self.err = E;
  }

  // decrypt message body and return the inner
  self.decrypt = function(body){
    if(!Buffer.isBuffer(body)) return false;
    if(body.length < 32+24+16) return false;

    var key = body.slice(0,32);
    var nonce = body.slice(32,32+24);
    var innerc = body.slice(32+24,body.length-16);

    var secret = sodium.crypto_box_beforenm(key, self.secret);

    // decipher the inner
    var zeros = new Buffer(Array(sodium.crypto_secretbox_BOXZEROBYTES)); // add zeros for nacl's api
    var inner = sodium.crypto_secretbox_open(Buffer.concat([zeros,innerc]),nonce,secret);
    
    return inner;
  };
}

exports.Remote = function(key)
{
  var self = this;
  try{
    if(!Buffer.isBuffer(key) || key.length != 32) throw new Error("invalid public key");
    self.endpoint = key;
    self.ephemeral = sodium.crypto_box_keypair();
    self.token = crypto.createHash('sha256').update(self.ephemeral.publicKey.slice(0,16)).digest().slice(0,16);
  }catch(E){
    self.err = E;
  }

  // verifies the hmac on an incoming message body
  self.verify = function(local, body){
    if(!Buffer.isBuffer(body)) return false;
    var mac1 = body.slice(body.length-16).toString("hex");
    var nonce = body.slice(32,32+24);

    var secret = sodium.crypto_box_beforenm(self.endpoint, local.secret);
    var akey = crypto.createHash('sha256').update(Buffer.concat([nonce,secret])).digest();
    var mac2 = sodium.crypto_onetimeauth(body.slice(0,body.length-16),akey).toString("hex");

    if(mac2 != mac1) return false;

    return true;
  };

  self.encrypt = function(local, inner){
    if(!Buffer.isBuffer(inner)) return false;

    // get the shared secret to create the iv+key for the open aes
    var secret = sodium.crypto_box_beforenm(self.endpoint, self.ephemeral.secretKey);
    var nonce = crypto.randomBytes(24);

    // encrypt the inner, encode if needed
    var innerc = sodium.crypto_secretbox(inner, nonce, secret);
    innerc = innerc.slice(sodium.crypto_secretbox_BOXZEROBYTES); // remove zeros from nacl's api
    var body = Buffer.concat([self.ephemeral.publicKey,nonce,innerc]);

    // prepend the line public key and hmac it  
    var secret = sodium.crypto_box_beforenm(self.endpoint, local.secret);
    var akey = crypto.createHash('sha256').update(Buffer.concat([nonce,secret])).digest();
    var mac = sodium.crypto_onetimeauth(body,akey);

    return Buffer.concat([body,mac]);
  };

}

exports.Ephemeral = function(remote, body)
{
  var self = this;
  
  try{
    // sender token
    self.token = crypto.createHash('sha256').update(body.slice(0,16)).digest().slice(0,16);

    // extract received ephemeral key
    var key = body.slice(0,32);

    var secret = sodium.crypto_box_beforenm(key, remote.ephemeral.secretKey);
    self.encKey = crypto.createHash("sha256")
      .update(secret)
      .update(remote.ephemeral.publicKey)
      .update(key)
      .digest();
    self.decKey = crypto.createHash("sha256")
      .update(secret)
      .update(key)
      .update(remote.ephemeral.publicKey)
      .digest();

  }catch(E){
    self.err = E;
  }

  self.decrypt = function(outer){
    // decrypt body
    var nonce = outer.slice(0,24);
    var cbody = outer.slice(24);

    var zeros = new Buffer(Array(sodium.crypto_secretbox_BOXZEROBYTES)); // add zeros for nacl's api
    var body = sodium.crypto_secretbox_open(Buffer.concat([zeros,cbody]),nonce,self.decKey);

    return body;
  };

  self.encrypt = function(inner){
    // now encrypt the packet
    var nonce = crypto.randomBytes(24);
    var cbody = sodium.crypto_secretbox(inner, nonce, self.encKey);
    cbody = cbody.slice(sodium.crypto_secretbox_BOXZEROBYTES); // remove zeros from nacl's api

    // return final body
    return Buffer.concat([nonce,cbody]);
  };
}


