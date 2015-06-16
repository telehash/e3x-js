var nacl = require("tweetnacl");
exports = module.exports = require('./cs3a.js');

// export a sodium->tweetnacl compat api wrapper
exports.sodium = function()
{
  var self = {};
     //From Buffer to Uint8Array:
  function toArray(buffer) {
    if(!buffer) buffer = new Buffer(0);
    var view = new Uint8Array(buffer.length);
    for (var i = 0; i < buffer.length; ++i) {
        view[i] = buffer[i];
    }
    return view;
  }
    //From ArrayBuffer to Buffer
   function toBuffer(ab) {
    if(!ab) return new Buffer(0);
    var buffer = new Buffer(ab.byteLength);
    var view = new Uint8Array(ab);
    for (var i = 0; i < buffer.length; ++i) {
        buffer[i] = view[i];
    }
    return buffer;
  }

  self.crypto_secretbox_BOXZEROBYTES = nacl.lowlevel.crypto_secretbox_BOXZEROBYTES;
  self.crypto_box_keypair = function(){
      var keypair = nacl.box.keyPair();
      return {publicKey:toBuffer(keypair.publicKey), secretKey:toBuffer(keypair.secretKey)};
  };
  self.crypto_box_beforenm = function(publickey, secretkey){
      var k = nacl.box.before(toArray(publickey), toArray(secretkey) );
      return toBuffer(k);
  };
  self.crypto_secretbox_open = function(ciphertextBin, nonceBin, keyBin){
    return toBuffer(nacl.secretbox.open(
        toArray(ciphertextBin.slice(self.crypto_secretbox_BOXZEROBYTES)),
        toArray(nonceBin),
        toArray(keyBin)
    ));
  }
  self.crypto_secretbox = function(msgBin, nonceBin, keyBin){
    var ret = toBuffer(nacl.secretbox(
        toArray(msgBin),
        toArray(nonceBin),
        toArray(keyBin)
    ));
    // grrr
    var z = new Buffer(self.crypto_secretbox_BOXZEROBYTES);
    return Buffer.concat([z,ret]);
  }
  self.crypto_onetimeauth = function(message, secretkey){
      var out = new Uint8Array(16);
      nacl.lowlevel.crypto_onetimeauth(out, 0, toArray(message), 0, message.length, toArray(secretkey));
      return toBuffer(out);
  }
  return self;
}

// deploy wrapper for browser
exports.crypt(exports.sodium());
