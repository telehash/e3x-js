var warn = function(a,b,c,d,e,f){console.log(a,b,c,d,e,f)};
var debug = function(a,b,c,d,e,f){console.log(a,b,c,d,e,f)};

// start a hashname listening and ready to go
function hashname(key, send, args)
{
  if(!key || !key.public || !key.private) {
    warn("bad args to hashname, requires key.public and key.private in forge rsa");
    return undefined;
  }
  if(typeof send !== "function")
  {
	  warn("second arg needs to be a function to send packets, is", typeof send);
		return undefined;
  }
  if(!args) args = {};

  // configure defaults
  var self = {seeds:[], lines:{}, all:{}, buckets:[], customs:{}};
	self.send = send; // external sending function
  self.private = key.private;
  self.public = key.public;
  self.hashname = key2hn(self.public);
	self.der = asn1.toDer(pki.publicKeyToAsn1(self.public)).bytes();
  self.nat = true;
  if(args.family) self.family = args.family;

  // udp socket
  var counter = 1;
  self.onMessage = function(msg, from){
    var packet = pdecode(msg);
    if(!packet) return warn("failed to decode a packet from", from.ip, from.port, msg.toString());
    if(Object.keys(packet.js).length == 0) return; // empty packets are NAT pings
    if(typeof packet.js.iv != "string" || packet.js.iv.length != 32) return warn("missing initialization vector (iv)", packet.sender);

    packet.sender = {ip:from.ip, port:from.port};
    packet.id = counter++;
    packet.at = Date.now();
    debug("in",packet.sender.ip+":"+packet.sender.port, packet.js.type, packet.body && packet.body.length);

    // either it's an open
    if(packet.js.type == "open") return inOpen(self, packet);

    // or it's a line
    if(packet.js.type == "line") return inLine(self, packet);
    
    if(Object.keys(packet.js).length > 0) warn("dropping incoming packet of unknown type", packet.js, packet.sender);
  };
  
  // need some seeds to connect to
  self.addSeed = function(arg) {
    if(arg) arg.public = pki.publicKeyFromPem(arg.pubkey);
    if(!arg.ip || !arg.port || !arg.public) return warn("invalid args to addSeed");
    var seed = self.seen(key2hn(arg.public));
    seed.public = arg.public;
    seed.ip = arg.ip;
    seed.port = parseInt(arg.port);
    self.seeds.push(seed);
  }
	
	// internal functions
	self.seen = seen;
  
  // connect to the network
  self.online = online;

  // create your own custom streams
  self.stream = function(hn, type, handler) {return addStream(self, self.seen(hn), "_"+type, handler); };

  // handle new streams coming in
  self.listen = function(type, callback) {
    if(typeof type != "string") return warn("bad arg given for handler, needs string and is", typeof type);
    self.customs[type] = callback;
  };
  
  return self;
}

function seen(hashname)
{
	var self = this;
  // validations
  if(!hashname) { warn("seen called without a hashname", hashname); return false; }
  if(typeof hashname != "string") { warn("wrong type, should be string", typeof hashname,hashname); return false; }
  hashname = hashname.split(",")[0]; // convenience if an address is passed in
  if(!isHEX(hashname, 64)) { warn("seen called without a valid hashname", hashname); return false; }

  // so we can check === self
  if(hashname === self.hashname) return self;

  var ret = self.all[hashname];
  if(!ret) {
    ret = self.all[hashname] = {hashname:hashname, chans:{}};
    ret.at = Date.now();
  }
  return ret;
}

function online(callback)
{
	var self = this;
	self.onlineCB = callback;
	self.seeds.forEach(function(seed){
		sendOpen(self, seed);
	})
}

// direct overrides the ipp of to
function sendOpen(self, to, direct)
{
  debug("sendOpen sending", to.hashname);
  to.sentOpen = true;
	var open = openize(self, to);
  self.lines[to.lineOut] = to;
  self.send(direct||to, open);
}

// any signature must be validated and then the body decrypted+processed
function inOpen(self, packet)
{
	var open = deopenize(self, packet);
	if(!open) return warn("couldn't decode open");	
  var from = self.seen(key2hn(open.rsa));
	if(!from) return warn("invalid hashname",key2hn(open.rsa),open.rsa);

  // make sure this open is newer (if any others)
  if(typeof open.js.at != "number" || (from.openAt && open.js.at < from.openAt)) return warn("invalid at", open.js.at);

  // update values
  debug("inOpen verified", from.hashname);
  from.openAt = open.js.at;
  from.public = open.rsa;
  from.ip = packet.sender.ip;
  from.port = packet.sender.port;
  from.address = [from.hashname, from.ip, from.port].join(",");
  from.recvAt = Date.now();

  // was an existing line already, being replaced
  if(from.lineIn && from.lineIn !== open.js.line) {
    debug("changing lines",from.hashname);
    from.sentOpen = false; // trigger resending them our open again
  }

  // do we need to send them an open yet?
  if(!from.sentOpen) sendOpen(self, from);

  // line is open now!
  from.lineIn = open.js.line;
  var ecdhe = ecdh(from.ecc.private, open.ecc);
  debug("ECDHE",ecdhe.length, ecdhe.toString("hex"));
	var md = forge.md.sha256.create()
	md.update(ecdhe);
	md.update(forge.util.hexToBytes(from.lineOut));
	md.update(forge.util.hexToBytes(from.lineIn));
	from.encKey = md.digest().bytes();
	var md = forge.md.sha256.create()
	md.update(ecdhe);
	md.update(forge.util.hexToBytes(from.lineIn));
	md.update(forge.util.hexToBytes(from.lineOut));
	from.decKey = md.digest().bytes();
	
	from.send = function(packet)
	{
		self.send(from,lineize(from,packet));
	}
	
	// TODO temp hack
	if(self.onlineCB)
	{
		self.onlineCB(null,from);
		delete self.onlineCB;
	}
}

// line packets must be decoded first
function inLine(self, packet){
  packet.from = self.lines[packet.js.line];

  // a matching line is required to decode the packet
  if(!packet.from) return debug("unknown line received", packet.js.line, packet.sender);

  packet.from.recvAt = Date.now();

	// decrypt the contained packet
	var md = forge.md.sha256.create();
	md.update(packet.from.decKey);
	var cipher = forge.aes.createDecryptionCipher(md.digest(), "CTR");
	cipher.start(forge.util.hexToBytes(packet.js.iv));
	cipher.update(forge.util.createBuffer(packet.body));
	cipher.finish();
	if(!cipher.output) return warn("couldn't decrypt packet",packet.js.line, packet.sender);
	var deciphered = pdecode(cipher.output);
	if(!deciphered) return warn("invalid decrypted packet", cipher.output);
  packet.js = deciphered.js;
  packet.body = deciphered.body;
  
  // now let the stream processing happen
  inStream(self, packet);
}

function inStream(self, packet)
{
	debug("inStream",packet);
}