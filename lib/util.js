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
  var jsbuf = js?forge.util.createBuffer(JSON.stringify(js), "utf8"):"";
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
	if(len > 0)
	{
	  try{ js = JSON.parse(jsonb); } catch(E){ return console.log("parse failed",jsonb) && false; }		
	}else{
		js = {};
	}
  return {js:js, body:body};
}

// some hash/hex handling utilities... these are NOT optimized at all

// just return true/false if it's at least the format of a sha1
function isHEX(str, len)
{
  if(typeof str !== "string") return false;
  if(str.length !== len) return false;
  if(str.replace(/[a-f0-9]+/i, "").length !== 0) return false;
  return true;
}

// XOR distance between two hex strings, high is furthest bit, 0 is closest bit, -1 is error
function dhash(h1, h2) {
  // convert to nibbles, easier to understand
  var n1 = hex2nib(h1);
  var n2 = hex2nib(h2);
  if(!n1.length || n1.length != n2.length) return -1;
  // compare nibbles
  var sbtab = [-1,0,1,1,2,2,2,2,3,3,3,3,3,3,3,3];
  var ret = 252;
  for (var i = 0; i < n1.length; i++) {
      var diff = n1[i] ^ n2[i];
      if (diff) return ret + sbtab[diff];
      ret -= 4;
  }
  return -1; // samehash
}

// convert hex string to nibble array
function hex2nib(hex)
{
  var ret = [];
  for (var i = 0; i < str.length / 2; i ++) {
      var bite = parseInt(str.substr(i * 2, 2), 16);
      if (isNaN(byt)) return [];
      ret[ret.length] = bite >> 4;
      ret[ret.length] = bite & 0xf;
  }
  return ret;
}
