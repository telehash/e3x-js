// this file contains all the crypto and binary/buffer functions
// it must be required after thjs is loaded, so that it binds all of it's functions into it

(function(exports){

// externally add forge lib dependencies
var forge, rsa, pki, asn1;
exports.forge = function(lib)
{
  forge = lib;
  pki = lib.pki;
  rsa = pki.rsa;
  asn1 = lib.asn1;
  return exports;
}

var sjcl;
exports.sjcl = function(lib)
{
  sjcl = lib;
}

exports.randomHEX = randomHEX;
exports.openize = openize;
exports.deopenize = deopenize;
exports.openline = openline;
exports.lineize = lineize;
exports.delineize = delineize;
exports.pencode = pencode;
exports.pdecode = pdecode;
try{thjs.localize(exports)}catch(E){}


var CS = {"1a":{},"2a":{}};
exports.CS = CS;

exports.lineid = function(bin)
{
  if(!bin) return "";
  return forge.util.bytesToHex(bin.substr(0,16));
}

exports.hashHEX = function(bin)
{
  if(!bin) return "";
  return forge.util.bytesToHex(forge.md.sha256.create().update(bin).digest().bytes());
}

exports.parts2hn = function(parts)
{
  var digests = [];
  var rollup = "";
  Object.keys(parts).sort().forEach(function(id){
    rollup = forge.md.sha256.create().update(rollup+id).digest().bytes();
    rollup = forge.md.sha256.create().update(rollup+parts[id]).digest().bytes();
  });
  return forge.util.bytesToHex(rollup);
}

exports.getkey = function(id, csid)
{
  return id.cs && id.cs[csid] && id.cs[csid].key;
}

exports.loadkeys = function(id, keys)
{
  id.cs = {};
  id.keys = {}; // for convenience
  var err = false;
  Object.keys(id.parts).forEach(function(csid){
    id.keys[csid] = keys[csid];
    id.cs[csid] = {};
    if(!CS[csid]) err = csid+" not supported";
    err = err||CS[csid].loadkey(id.cs[csid], keys[csid], keys[csid+"_secret"]);
  });
  return err;
}

exports.loadkey = function(id, csid, key)
{
  id.csid = csid;
  return CS[csid].loadkey(id, key);
}

exports.genkeys = function(cbDone,cbStep,sets)
{
  if(!sets) sets = {"1a":true,"2a":true}; // default sets to create
  var ret = {parts:{}};
  var todo = Object.keys(sets).filter(function(csid){ return CS[csid];});
  if(todo.length == 0) return cbDone("no sets supported");
  function pop(err)
  {
    if(err) return cbDone(err);
    var csid = todo.pop();
    if(!csid) return cbDone(null, ret);
    CS[csid].genkey(ret,pop,cbStep);
  }
  pop();
}

CS["1a"] = {
  genkey:function(ret,cbDone,cbStep)
  {
    var k = ecKey("secp160r1",20);
    ret["1a"] = forge.util.encode64(k.public.uncompressed);
    ret["1a_secret"] = forge.util.encode64(k.private.uncompressed);
    ret.parts["1a"] = forge.md.sha1.create().update(k.public.uncompressed).digest().toHex();
    cbDone();
  },
  
  loadkey:function(id, pub, priv)
  {
    id.key = (pub.length == 40) ? pub : forge.util.decode64(pub);
    if(id.parts && id.parts["1a"] != forge.md.sha1.create().update(id.key).digest().toHex()) return "fingerprint mismatch";
    id.public = ecPub(id.key, "secp160r1", 20);
    if(!id.public) return "wrong size";
    if(priv)
    {
      var bytes = (priv.length == 20) ? priv : forge.util.decode64(priv);
      id.private = new BigInteger(unstupid(forge.util.bytesToHex(bytes),40), 16);    
    }
    return false;
  },

  openize:function(id, to, inner)
  {
    if(!to.ecc) to.ecc = ecKey("secp160r1", 20);
    // get the shared secret to create the iv+key for the open aes
    var secret = unstupid(ecdh(to.ecc.private, to.public),40);
  //  console.log("ECDHE O",secret.length, secret, forge.util.bytesToHex(to.key), forge.util.bytesToHex(to.ecc.key));
    var key = secret.substr(0,32);
    var iv = "00000000000000000000000000000001";

    // aes-128 the open
  	var ibody = pencode(inner, id.cs["1a"].key);
  	var cipher = forge.aes.createEncryptionCipher(forge.util.hexToBytes(key), "CTR");
  	cipher.start(forge.util.hexToBytes(iv));
  	cipher.update(ibody);
  	cipher.finish();
  
    // prepend the line public key and hmac it  
    var secret = unstupid(ecdh(id.cs["1a"].private, to.public),40);
    var macd = forge.util.createBuffer();
    macd.putBytes(to.ecc.key);
    macd.putBytes(cipher.output.bytes());
    var hmac = forge.hmac.create();
    hmac.start("sha1", forge.util.hexToBytes(secret));
    hmac.update(macd.bytes());
  
    // create final body
    var body = forge.util.createBuffer();
    body.putBytes(hmac.digest().bytes());
    body.putBytes(macd.bytes());
    return pencode(0x1a, body);
  },
  
  deopenize:function(id, open)
  {
    var ret = {verify:false};
    if(!open.body) return ret;
    var body = forge.util.createBuffer(open.body);
    var mac1 = body.getBytes(20);
    var pub = body.bytes(40);
    ret.linepub = ecPub(pub, "secp160r1", 20);
    if(!ret.linepub) return ret;
    var secret = unstupid(ecdh(id.cs["1a"].private, ret.linepub),40);
  //  console.log("ECDHE D",secret.length, secret, forge.util.bytesToHex(id.cs["1a"].key), forge.util.bytesToHex(pub));
    var key = secret.substr(0,32);
    var iv = "00000000000000000000000000000001";
    var mbody = body.bytes();

    // aes-128 decipher the inner
    body.getBytes(40); // remove the prefixed key
  	var cipher = forge.aes.createDecryptionCipher(forge.util.hexToBytes(key), "CTR");
  	cipher.start(forge.util.hexToBytes(iv));
  	cipher.update(body);
  	cipher.finish();
  	var inner = pdecode(cipher.output);
    if(!inner) return ret;

    // verify+load inner key info
    var pub = ecPub(inner.body, "secp160r1", 20);
    if(!pub) return ret;
    ret.key = inner.body;
    if(typeof inner.js.from != "object" || !inner.js.from["1a"]) return ret;
    if(forge.md.sha1.create().update(inner.body).digest().toHex() != inner.js.from["1a"]) return ret;

    // verify the hmac
    var secret = unstupid(ecdh(id.cs["1a"].private, pub),40);
    var hmac = forge.hmac.create();
    hmac.start("sha1", forge.util.hexToBytes(secret));
    hmac.update(mbody);
    var mac2 = hmac.digest().bytes();
    if(mac2 != mac1) return ret;
  
    // all good, cache+return
    ret.verify = true;
    ret.js = inner.js;
//    console.log("INNER",inner.js,ret.key.length);
    return ret;
  },
 
  // set up the line enc/dec keys
  openline:function(from, open)
  {
    from.lineIV = 0;
    var ecdhe = ecdh(from.ecc.private, open.linepub);
//    console.log("ECDHE LINE",ecdhe.length, ecdhe, from.lineOut, from.lineIn);
  	var md = forge.md.sha1.create()
  	md.update(forge.util.hexToBytes(ecdhe));
  	md.update(forge.util.hexToBytes(from.lineOut));
  	md.update(forge.util.hexToBytes(from.lineIn));
  	from.encKey = forge.util.createBuffer(md.digest().getBytes(16));
  	var md = forge.md.sha1.create()
  	md.update(forge.util.hexToBytes(ecdhe));
  	md.update(forge.util.hexToBytes(from.lineIn));
  	md.update(forge.util.hexToBytes(from.lineOut));
  	from.decKey = forge.util.createBuffer(md.digest().getBytes(16));
  },

  lineize:function(to, packet)
  {
    var iv = forge.util.hexToBytes(unstupid((to.lineIV++).toString(16),8));
  	var buf = pencode(packet.js,packet.body);

  	// now encrypt the packet
  	var cipher = forge.aes.createEncryptionCipher(to.encKey.copy(), "CTR");
  	cipher.start(forge.util.hexToBytes(unstupid(forge.util.bytesToHex(iv),32))); // padd out the IV to 16 bytes
  	cipher.update(buf);
  	cipher.finish();

    // prepend the IV and hmac it
    var macd = forge.util.createBuffer();
    macd.putBytes(iv);
    macd.putBytes(cipher.output.bytes());
    var hmac = forge.hmac.create();
    hmac.start("sha1", to.encKey.bytes());
    hmac.update(macd.bytes());
  
    // create final body
    var body = forge.util.createBuffer();
    body.putBytes(forge.util.hexToBytes(to.lineIn));
    body.putBytes(hmac.digest().bytes(4));
    body.putBytes(macd.bytes());

    return pencode(null, body);
  },

  delineize:function(from, packet)
  {
    if(!packet.body) return "no body";
    var body = forge.util.createBuffer(packet.body);
    var lineID = body.getBytes(16);
    var mac = body.getBytes(4);
    var hmac = forge.hmac.create();
    hmac.start("sha1", from.decKey.bytes());
    hmac.update(body.bytes());
    if(hmac.digest().bytes(4) != mac) return "invalid hmac";

    var iv = body.getBytes(4);
  	var cipher = forge.aes.createDecryptionCipher(from.decKey.copy(), "CTR");
  	cipher.start(forge.util.hexToBytes(unstupid(forge.util.bytesToHex(iv),32)));
  	cipher.update(body);
  	cipher.finish();
  	if(!cipher.output) return "cipher failed";
  	var deciphered = pdecode(cipher.output);
  	if(!deciphered) return "invalid decrypted packet";
    packet.js = deciphered.js;
    packet.body = deciphered.body;
    return false;
  }
}

CS["2a"] = {
  genkey:function(ret,cbDone,cbStep)
  {
  	var state = rsa.createKeyPairGenerationState(2048, 0x10001);
  	var step = function() {
  	  // run for 100 ms
  	  if(!rsa.stepKeyPairGenerationState(state, 100)) {
        if(cbStep) cbStep();
  	    setTimeout(step, 10);
  	  } else {
        var key = asn1.toDer(pki.publicKeyToAsn1(state.keys.publicKey)).bytes();
        ret["2a"] = forge.util.encode64(key);
        ret["2a_secret"] = forge.util.encode64(asn1.toDer(pki.privateKeyToAsn1(state.keys.privateKey)).bytes());
        var md = forge.md.sha256.create();
        md.update(key);
        ret.parts["2a"] = md.digest().toHex();
        cbDone();
  	  }
  	}
  	setTimeout(step);  
  },

  loadkey:function(id, pub, priv)
  {
    // take pki or ber format
    if(pub.length > 300)
    {
      if(pub.substr(0,1) == "-") pub = asn1.toDer(pki.publicKeyToAsn1(pki.publicKeyFromPem(key))).bytes();
      else pub = forge.util.decode64(pub);
    }
    id.key = pub;
    id.public = pki.publicKeyFromAsn1(asn1.fromDer(pub));    
    // private is only pem/ber format
    if(priv)
    {
      if(priv.substr(0,1) == "-") id.private = pki.privateKeyFromPem(priv);
      else id.private = pki.privateKeyFromAsn1(asn1.fromDer(forge.util.decode64(priv)));
    }
    return false;
  },
  
  openize:function(id, to, inner)
  {
  	if(!to.ecc) to.ecc = ecKey("secp256r1",32);
    var pubhex = forge.util.bytesToHex(to.ecc.key);

    // create the aes key/iv
  	var md = forge.md.sha256.create();
  	md.update(to.ecc.key);
    var digest = md.digest().bytes();
    var key = new sjcl.cipher.aes(sjcl.codec.hex.toBits(forge.util.bytesToHex(digest)));
    var iv = sjcl.codec.hex.toBits(unstupid("1",32));

  	// now encrypt the body    
  	var ibody = pencode(inner, id.cs["2a"].key);
    var cipher = sjcl.mode.gcm.encrypt(key, sjcl.codec.hex.toBits(forge.util.bytesToHex(ibody.bytes())), iv, [], 128);
    var cbody = forge.util.hexToBytes(sjcl.codec.hex.fromBits(cipher));
  //  console.log("SJCL",cbody.length, ibody.length());

  	// sign & encrypt the sig
  	var md = forge.md.sha256.create();
  	md.update(cbody);
  	var sig = id.cs["2a"].private.sign(md);
  	var md = forge.md.sha256.create();
  	md.update(to.ecc.key+forge.util.hexToBytes(to.lineOut));
    var key = new sjcl.cipher.aes(sjcl.codec.hex.toBits(forge.util.bytesToHex(md.digest().bytes())));
    var cipher = sjcl.mode.gcm.encrypt(key, sjcl.codec.hex.toBits(forge.util.bytesToHex(sig)), iv, [], 32);
    var csig = forge.util.hexToBytes(sjcl.codec.hex.fromBits(cipher));

  	// encrypt the ecc key
    var ekey = to.public.encrypt(to.ecc.key, "RSA-OAEP");
  
    var body = forge.util.createBuffer();
    body.putBytes(ekey);
    body.putBytes(csig);
    body.putBytes(cbody);

  	var packet = pencode(0x2a, body);
  	return packet;
  },
  
  deopenize:function(id, open)
  {
    var ret = {verify:false};
    if(!open.body) return ret;
    var body = forge.util.createBuffer(open.body);
    var ekey = body.getBytes(256);
    var csig = body.getBytes(260);

    // decrypt the line key and use it for the aes key
  	var ecpub = id.cs["2a"].private.decrypt(ekey, "RSA-OAEP");
    ret.linepub = ecPub(ecpub,"secp256r1",32);
    if(!ret.linepub) return ret;
  	var md = forge.md.sha256.create();
  	md.update(ecpub);
    var key = new sjcl.cipher.aes(sjcl.codec.hex.toBits(forge.util.bytesToHex(md.digest().bytes())));
    var iv = sjcl.codec.hex.toBits(unstupid("1",32));

  	// now decrypt the inner    
    var cipher = sjcl.mode.gcm.decrypt(key, sjcl.codec.hex.toBits(forge.util.bytesToHex(body.bytes())), iv, [], 128);
    var ibody = forge.util.hexToBytes(sjcl.codec.hex.fromBits(cipher));
    var inner = pdecode(ibody);
  //  console.log(inner);
    if(!inner || !inner.js.line) return ret;

    ret.key = inner.body;
    ret.js = inner.js;
  	var rsapub = pki.publicKeyFromAsn1(asn1.fromDer(inner.body));
    if(!rsapub) return ret;

    // decrypt the signature
  	var md = forge.md.sha256.create();
  	md.update(ecpub+forge.util.hexToBytes(inner.js.line));
    var key = new sjcl.cipher.aes(sjcl.codec.hex.toBits(forge.util.bytesToHex(md.digest().bytes())));
    var cipher = sjcl.mode.gcm.decrypt(key, sjcl.codec.hex.toBits(forge.util.bytesToHex(csig)), iv, [], 32);
    var sig = forge.util.hexToBytes(sjcl.codec.hex.fromBits(cipher));

    // validate it
  	var md = forge.md.sha256.create();
  	md.update(body.bytes());
    var digest = md.digest().bytes();
    try{ ret.verify = rsapub.verify(digest, sig); }catch(E){ var err=E; }

//    console.log("INNER",err,ret.js,ret.key.length,forge.util.bytesToHex(digest));
    return ret;
  },
  
  openline:function(from, open)
  {
    var ecdhe = ecdh(from.ecc.private, open.linepub);
//    console.log("ECDHE",ecdhe.length, ecdhe, from.lineOut, from.lineIn);
  	var md = forge.md.sha256.create()
  	md.update(forge.util.hexToBytes(ecdhe));
  	md.update(forge.util.hexToBytes(from.lineOut));
  	md.update(forge.util.hexToBytes(from.lineIn));
    from.encKey = new sjcl.cipher.aes(sjcl.codec.hex.toBits(forge.util.bytesToHex(md.digest().bytes())));
  	var md = forge.md.sha256.create()
  	md.update(forge.util.hexToBytes(ecdhe));
  	md.update(forge.util.hexToBytes(from.lineIn));
  	md.update(forge.util.hexToBytes(from.lineOut));
    from.decKey = new sjcl.cipher.aes(sjcl.codec.hex.toBits(forge.util.bytesToHex(md.digest().bytes())));
  //	console.log("encKey",from.encKey.toHex(),"decKey",from.decKey.toHex());
  },

  lineize:function(to, packet)
  {
  	var iv = forge.random.getBytesSync(16);
  	var buf = pencode(packet.js,packet.body);

  	// now encrypt the packet
    var cipher = sjcl.mode.gcm.encrypt(to.encKey, sjcl.codec.hex.toBits(forge.util.bytesToHex(buf.bytes())), sjcl.codec.hex.toBits(forge.util.bytesToHex(iv)), [], 128);
    var cbody = forge.util.hexToBytes(sjcl.codec.hex.fromBits(cipher));

    var body = forge.util.createBuffer();
    body.putBytes(forge.util.hexToBytes(to.lineIn));
    body.putBytes(iv);
    body.putBytes(cbody);

  	return pencode(null,body);
  },

  // decrypt the contained packet
  delineize:function(from, packet)
  {
    if(!packet.body) return "no body";
    var cbody = forge.util.createBuffer(packet.body);
    var lineID = cbody.getBytes(16);
    var iv = sjcl.codec.hex.toBits(forge.util.bytesToHex(cbody.getBytes(16)));
  
    try{
      var cipher = sjcl.mode.gcm.decrypt(from.decKey, sjcl.codec.hex.toBits(forge.util.bytesToHex(cbody.bytes())), iv, [], 128);    
    }catch(E){
      return E;
    }
    if(!cipher) return "no cipher output";
    var deciphered = pdecode(forge.util.hexToBytes(sjcl.codec.hex.fromBits(cipher)));
  	if(!deciphered) return "invalid decrypted packet";

    packet.js = deciphered.js;
    packet.body = deciphered.body;
    return false;
  }
}

function ecPub(pub, curve, bytes)
{
  if(pub.length != bytes*2) return false;
  var curve = getSECCurveByName(curve).getCurve();
  var uncompressed = forge.util.createBuffer(pub);
  var x = uncompressed.getBytes(bytes);
  var y = uncompressed.getBytes();
  return new ECPointFp(curve,
    curve.fromBigInteger(new BigInteger(unstupid(forge.util.bytesToHex(x),bytes), 16)),
    curve.fromBigInteger(new BigInteger(unstupid(forge.util.bytesToHex(y),bytes), 16)));
}

// return random bytes, in hex
function randomHEX(len)
{
	return unstupid(forge.util.bytesToHex(forge.random.getBytesSync(len)),len*2);
}

// zero prepad
function unstupid(hex,len)
{
	return (hex.length >= len) ? hex : unstupid("0"+hex,len);
}

function ecKey(curve, bytes)
{
	var c = getSECCurveByName(curve);
	//var curve = new ECCurveFp(c.getCurve().getQ(), c.getCurve().getA().toBigInteger(), c.getCurve().getB().toBigInteger());
	//console.log(curve);
	var n = c.getN();
	var n1 = n.subtract(BigInteger.ONE);
	var r = new BigInteger(n.bitLength(), new SecureRandom());
	var priecc = r.mod(n1).add(BigInteger.ONE);
	priecc.uncompressed = forge.util.hexToBytes(unstupid(priecc.toString(16),bytes*2));
	//console.log(priecc);

//	var G = new ECPointFp(c.getCurve(), c.getCurve().fromBigInteger(c.getG().getX().toBigInteger(), c.getG().getY().toBigInteger());
	//console.log(G);
	var P = c.getG().multiply(priecc);
	var pubhex = unstupid(P.getX().toBigInteger().toString(16),bytes*2)+unstupid(P.getY().toBigInteger().toString(16),bytes*2);
	P.uncompressed = forge.util.hexToBytes(pubhex);
	//console.log(forge.util.createBuffer(forge.util.hexToBytes(P.getX().toBigInteger().toString(16))).toHex());
//  console.log(P.uncompressed.length,pubhex,forge.util.bytesToHex(P.uncompressed));
	return {curve:c, private:priecc, public:P, key:P.uncompressed};
}


function openize(id, to)
{
  if(!to.csid)
  {
    console.log("can't open w/ no key");
    return undefined;
  }
	if(!to.lineOut) to.lineOut = randomHEX(16);
  if(!to.lineAt) to.lineAt = Date.now();
	var inner = {}
	inner.at = to.lineAt; // always the same for the generated line id/key
	inner.to = to.hashname;
  inner.from = id.parts;
	inner.line = to.lineOut;
  return CS[to.csid].openize(id, to, inner);
}

function deopenize(id, open)
{
//  console.log("DEOPEN",open.body.length);
  var ret;
  var csid = open.head.charCodeAt().toString(16);
  if(!CS[csid]) return {err:"unknown CSID of "+csid};
  try{ret = CS[csid].deopenize(id, open);}catch(E){return {err:E};}
  ret.csid = csid;
  return ret;
}

// set up the line enc/dec keys
function openline(from, open)
{
  from.csid = open.csid;
  CS[open.csid].openline(from, open);
}

// encrypt the packet
function lineize(to, packet)
{
  return CS[to.csid].lineize(to, packet);
}

// decrypt the packet
function delineize(from, packet)
{
  return CS[from.csid].delineize(from, packet);
}

function ecdh(priv, pub) {
  if(!priv || !pub) return "00";
  var S = pub.multiply(priv);
  return S.getX().toBigInteger().toString(16);
}

// encode a packet
function pencode(js, body)
{
  var head = (typeof js == "number") ? forge.util.createBuffer(String.fromCharCode(js)) : forge.util.createBuffer(js?JSON.stringify(js):"", "utf8");
  var len = head.length();
  var ret = forge.util.createBuffer();
  // network order
  ret.putInt16(len);
  ret.putBytes(head.getBytes());
  if(typeof body == "string") body = forge.util.createBuffer(body);
  if(body) ret.putBytes(body.bytes());
  return ret;
}

// packet decoding
function pdecode(packet)
{
  packet = (typeof packet == "string") ? forge.util.createBuffer(packet) : packet.copy();
  var len = packet.getInt16(packet);
  if(packet.length() < len) return false;
  var head = packet.getBytes(len);
  var body = packet.getBytes();
  var js;
	if(len > 1)
	{
	  try{ js = JSON.parse(head); } catch(E){
      console.log("parse failed",E,jsonb);
      return false;
    }
	}else{
		js = {};
	}
  return {js:js, length:packet.length(), head:head, body:body};
}

})(typeof exports === 'undefined'? this['thcrypt']={}: exports);