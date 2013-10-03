// zero prepad
function unstupid(hex,len)
{
	return (hex.length >= len) ? hex : unstupid("0"+hex,len);
}

function ecKey()
{
	var c = getSECCurveByName("secp256r1");
	//var curve = new ECCurveFp(c.getCurve().getQ(), c.getCurve().getA().toBigInteger(), c.getCurve().getB().toBigInteger());
	//console.log(curve);
	var n = c.getN();
	var n1 = n.subtract(BigInteger.ONE);
	var r = new BigInteger(n.bitLength(), new SecureRandom());
	var priecc = r.mod(n1).add(BigInteger.ONE);
	//console.log(priecc);

	//var G = new ECPointFp(c.getCurve(), c.getCurve().fromBigInteger(c.getG().getX().toBigInteger(), c.getG().getY().toBigInteger());
	//console.log(G);
	var P = c.getG().multiply(priecc);
	var pubhex = "04"+unstupid(P.getX().toBigInteger().toString(16),32)+unstupid(P.getY().toBigInteger().toString(16),32);
	P.uncompressed = forge.util.hexToBytes(pubhex);
	//console.log(forge.util.createBuffer(forge.util.hexToBytes(P.getX().toBigInteger().toString(16))).toHex());
  console.log(P.uncompressed.length,pubhex,forge.util.bytesToHex(P.uncompressed));
	return {curve:c, private:priecc, public:P};
}

function openize(id, to)
{
	if(!to.ecc) to.ecc = ecKey();
	if(!to.lineOut) to.lineOut = forge.util.bytesToHex(forge.random.getBytesSync(16));
	var inner = {}
	inner.at = Date.now();
	inner.to = to.hashname;
	inner.line = to.lineOut;
	var body = pencode(inner, id.der);
	var open = {type:"open"};
	var iv = forge.random.getBytesSync(16);
	open.iv = forge.util.bytesToHex(iv);

	// now encrypt the body
	var md = forge.md.sha256.create();
	md.update(to.ecc.public.uncompressed);
	var cipher = forge.aes.createEncryptionCipher(md.digest(), "CTR");
	cipher.start(iv);
	cipher.update(body);
	cipher.finish();
	body = cipher.output;

	// sign
	var md = forge.md.sha256.create();
	md.update(body.bytes());
	open.sig = forge.util.encode64(id.private.sign(md));

	// encrypt the ecc key
	open.open = forge.util.encode64(to.public.encrypt(to.ecc.public.uncompressed, "RSA-OAEP"));
	console.log(open, body.length());
	var packet = pencode(open, body.bytes());
	return packet.bytes();
}

function deopenize(id, open)
{
	// decrypt the ecc key
	var dec = forge.util.decode64(open.js.open);
	var ecpub = id.private.decrypt(dec, "RSA-OAEP");
	console.log(ecpub.length);
	// compose the aes key
	var md = forge.md.sha256.create();
	md.update(ecpub);
	var cipher = forge.aes.createDecryptionCipher(md.digest(), "CTR");
	cipher.start(forge.util.hexToBytes(open.js.iv));
	cipher.update(forge.util.createBuffer(open.body));
	cipher.finish();
	var inner = pdecode(cipher.output);
	console.log(inner);
	var rsapub = pki.publicKeyFromAsn1(asn1.fromDer(inner.body));
	console.log("from", key2hn(rsapub));
	var md = forge.md.sha256.create()
	md.update(open.body);
	var verify = rsapub.verify(md.digest().bytes(), forge.util.decode64(open.js.sig));
	console.log("verify", verify);
	return {ecc:ecpub, rsa:rsapub, js:inner.js};
}

// encrypt the packet
function lineize(to, packet)
{
	var wrap = {type:"line"};
	wrap.line = to.lineIn;
	var iv = forge.random.getBytesSync(16);
	wrap.iv = forge.util.bytesToHex(iv);
	// now encrypt the packet
	var md = forge.md.sha256.create();
	md.update(to.encKey);
	var cipher = forge.aes.createEncryptionCipher(md.digest(), "CTR");
	cipher.start(iv);
	cipher.update(packet);
	cipher.finish();
	return pencode(wrap,cipher.output.bytes()).bytes();
}

function ecdh(priv, pubbytes) {
  var curve = getSECCurveByName("secp256r1").getCurve();
  var uncompressed = forge.util.createBuffer(pubbytes);
//console.log(uncompressed.length(), uncompressed.bytes());
  uncompressed.getByte(); // chop off the 0x04
  var x = uncompressed.getBytes(32);
  var y = uncompressed.getBytes(32);
//console.log(x.length, y.length);
  if(y.length != 32) return false;
  var P = new ECPointFp(curve,
    curve.fromBigInteger(new BigInteger(forge.util.bytesToHex(x), 16)),
    curve.fromBigInteger(new BigInteger(forge.util.bytesToHex(y), 16)));
  var S = P.multiply(priv);
  return S.getX().toBigInteger().toString(16);
}
