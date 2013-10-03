// pem format string key to string hashname
function key2hn(pubkey)
{
	var der = asn1.toDer(pki.publicKeyToAsn1(pubkey));
	var md = forge.md.sha256.create();
	md.update(der.getBytes());
	return md.digest().toHex();	
}


// encode a packet
function pencode(js, body)
{

  var jsbuf = forge.util.createBuffer(JSON.stringify(js), "utf8");
  var len = jsbuf.length()
  var ret = forge.util.createBuffer();
  // network order
  ret.putInt16(len);
  ret.putBytes(jsbuf.getBytes());
  if(body) ret.putBytes(body);
  console.log(ret.length(),ret.toHex());
  return ret;
}

// packet decoding
function pdecode(packet)
{
  if(typeof packet == "string") packet = forge.util.createBuffer(packet);
  var len = packet.getInt16(packet);
  if(packet.length() < len) return console.log("json too short",len,packet.length()) && false;
  var jsonb = packet.getBytes(len);
  var body = packet.getBytes();
  var js;
  try{ js = JSON.parse(jsonb); } catch(E){ return console.log("parse failed",jsonb) && false; }
  return {js:js, body:body};
}
