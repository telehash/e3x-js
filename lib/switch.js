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

  // create your own custom channels
  self.connect = function(hn, js, body, cbDone) {
		if(!js || !js.type) return false;
		if(js.type.substr(0,1) != "_") js.type = "_"+js.type; // ensure is _prefix escaped
		var hn = self.seen(hn);
		var chan = hn.channel();
		var packet = chan.packet(js);
		packet.body = body;
		chan.send(packet, cbDone);
		return chan;
	};

  // handle new channels coming in
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
	if(ret) return ret;
  ret = self.all[hashname] = {hashname:hashname, chans:{}};
  ret.at = Date.now();
	ret.channel = function(id)
	{
		if(!id) id = randomHEX(16);
	  var chan = {inq:[], outq:[], inSeq:0, outSeq:0, inDone:-1, outConfirmed:0, inDups:0, lastAck:-1, type:"_"+type, id:id}
		ret.chans[id] = chan;
	  chan.hashname = hashname; // for convenience

		// create a packet that is valid for a channel's current state
		chan.packet = function(js)
		{
			// TODO all sequence/miss tracking stuff
			return {js:js};
		}

		// process packets at a raw level, handle all miss/ack tracking and ordering
		chan.receive = function(packet)
		{
			
		}
		
		// ordered processing, can be overridden
		chan.handle = function(packet, callback)
		{
			// TODO do onMessage stuff
			callback();
		}

		// set up how we pass data to channel handlers
		chan.on = function(event, cbEvent)
		{
			if(event === "error") chan.onError = cbEvent; // friendly end distinction
			if(event === "message") chan.onMessage = cbEvent; // js/body wrapper
			if(event === "packet") chan.onPacket = cbEvent; // raw
		}
		// default to onError/onMessage handling
		chan.onPacket = function(packet, cbDone)
		{
			if(packet.js.end)
			{
				if(chan.onError) chan.onError(chan, packet.js.err, packet.js["_"]||{}, packet.body);
				return;
			}
			if(!chan.onMessage) return;
			chan.onMessage(chan, packet.js["_"]||{}, packet.body);
			// by default there's no serialized handling
			cbDone();
		}

	  // handy util, send just one anytime explicitly
	  chan.message = function(js, body, cbAck){
	    js = {"_":js}; // wrap js for app streams
	    chan.send({js:js, body:body}, cbAck);
			return chan;
	  };
		
		chan.send = function(packet, cbAck)
		{
			if(!cbAck) cbAck = function(){};
		  if(!packet)
		  {
			  // these are just empty "ack" packets, drop if no reason to ack
		    if(chan.outConfirmed == chan.inSeq && !chan.inDups) return;
		    packet = {js:{}};
		  }
  
		  // always send the type only on the first outgoing packet (not in answer)
		  if(chan.inDone == -1 && chan.outSeq == 0) packet.js.type = chan.type;
		  packet.js.stream = chan.id;
		  packet.js.seq = chan.outSeq++;
		  packet.js.ack = chan.inSeq;
			
		  // calculate misses, if any
		  if(chan.inq.length > 0)
		  {
		    packet.js.miss = [];
		    for(var i = 0; i < chan.inq.length; i++)
		    {
		      if(!chan.inq[i]) packet.js.miss.push(chan.inDone + 1 + i);
		    }
		  }

		  // reset/update tracking stats
		  chan.outConfirmed = stream.inSeq;
		  chan.inDups = 0;
		  chan.ended = packet.js.end;

			// serialize out and send
			packet = pencode(packet.js, packet.body);
			if(!chan.lossy) chan.outq.push(packet);
			ret.line(packet);
			return chan;
		}

	  return chan;		
	}
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
  debug("inOpen verified", from.hashname, open);
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
  from.lineIn = open.js.line;

  // do we need to send them an open yet?
  if(!from.sentOpen) sendOpen(self, from);

  // line is open now!
	openline(from,open);
	from.line = function(packet)
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

	// decrypt
  delineize(packet);  
  packet.from.recvAt = Date.now();

  // now let the stream processing happen
  if(!dhash.isHEX(packet.js.stream, 32)) return warn("invalid stream value", packet.js.stream, packet.from.address);
  packet.js.seq = parseInt(packet.js.seq);
  if(!(packet.js.seq >= 0)) return warn("invalid sequence on stream", packet.js.seq, stream.id, packet.from.address);

	// either get existing, or create a new blank one (can't validate it yet due to out-of-order packets)
  var chan = (packet.from.chans[packet.js.stream]) ? packet.from.chans[packet.js.stream] : packet.from.channel("unknown", packet.js.stream);

  if(packet.js.seq > chan.inSeq) chan.inSeq = packet.js.seq;

  // lossy streams skip all the auto/ack party
  if(chan.lossy) return chan.onPacket(packet);

  // so, if there's a lot of "gap" or or dups coming in, be kind and send an update immediately, otherwise send one in a bit
  if(packet.js.seq - chan.outConfirmed > 30 || chan.inDups) chan.send();

  // track and drop duplicate packets
  if(packet.js.seq <= chan.inDone || chan.inq[packet.js.seq - (chan.inDone+1)]) return chan.inDups++;

  // process any valid newer incoming ack/miss
  var ack = parseInt(packet.js.ack);
  var miss = Array.isArray(packet.js.miss) ? packet.js.miss : [];
  if(miss.length > 100) return warn("too many misses", miss.length, chan.id, packet.from.address);
//console.log(">>>ACK", ack, stream.lastAck, stream.outSeq, "len", stream.outq.length, stream.outq.map(function(p){return p.js.seq}).join(","));
  if(ack > chan.lastAck && ack <= chan.outSeq)
  {
    chan.lastAck = ack;
    // rebuild outq, only keeping missed/newer packets
    var outq = stream.outq;
    chan.outq = [];
    outq.forEach(function(pold){
      // packet acknowleged!
      if(pold.js.seq <= ack && miss.indexOf(pold.js.seq) == -1) {
        if(pold.done) pold.done();
        return;
      }
      chan.outq.push(pold);
      if(miss.indexOf(pold.js.seq) == -1) return;
      // resend misses but not too frequently
      if(Date.now() - pold.resentAt < 5*1000) return;
      pold.resentAt = Date.now();
      packet.from.line(pold);
    });
//    console.log("OUTQLEN", stream.outq.length);
  }
  
  // drop out of bounds
  if(packet.js.seq - chan.inDone > 100) return warn("chan too far behind, dropping", chan.id, packet.from.address);

  // stash this seq and process any in sequence
  packet.chan = chan;
  chan.inq[packet.js.seq - (chan.inDone+1)] = packet;
  while(chan.inq[0])
  {
    packet = chan.inq.shift();
    chan.inDone++;
    // sends them to the async queue that calls inchanSeries()
    chan.q.push(packet);
  }
}

// worker on the ordered-packet-queue processing
function inStreamSeries(self, packet, callback)
{
  // everything from an outgoing stream has a handler
  if(packet.stream.handler) return packet.stream.handle(self, packet, callback);

  // only new incoming streams end up here, require a type
  if(typeof packet.js.type != "string") {
    if(!packet.js.end) warn("unknown stream packet", JSON.stringify(packet.js));
    return callback();
  }

  // branch out based on what type of stream it is
  if(packet.js.type === "sock") inSock(self, packet);
  else if(packet.js.type === "peer") inPeer(self, packet);
  else if(packet.js.type === "connect") inConnect(self, packet);
  else if(packet.js.type === "seek") inSeek(self, packet);
  else if(packet.js.type.indexOf("_") == 0 && self.customs[packet.js.type.substr(1)]) {
    packet.stream.app = true;
    packet.stream.handler = self.customs[packet.js.type.substr(1)];
    return packet.stream.handle(self, packet, callback);
  } else {
    warn("unknown stream packet type", packet.js.type);
    packet.stream.send({end:true, err:"unknown type"});
  }

  // if nobody is handling or has replied, automatically end it
  if(!packet.stream.handler && !packet.stream.ended) packet.stream.send({end:true});

  callback();
}


// someone's trying to connect to us, send an open to them
function inConnect(self, packet)
{
  var to = seen(self, key2hash(packet.body).toString());
  if(!to || !packet.js.ip || typeof packet.js.port != 'number') return warn("invalid connect request from",packet.from.address,packet.js);
  // if no ipp yet, save them
  if(!to.ip) {
    to.ip = packet.js.ip;
    to.port = parseInt(packet.js.port);
  }
  // if local given, cache that for the open flow too
  if(packet.js.local && typeof packet.js.local.ip == "string" && typeof packet.js.local.port == "number" && packet.js.local.ip != to.ip) to.local = packet.js.local;
  if(to.sentOpen)
  {
    // don't resend to fast to prevent abuse/amplification
    if(to.resentOpen && (Date.now() - to.resentOpen) < 5000) return warn("told to connect too fast, ignoring from",packet.from.address,"to",to.address, Date.now() - to.resentOpen);
    to.resentOpen = Date.now();
    to.sentOpen = false;
  }else{
    to.pubkey = packet.body;    
  }
  sendOpen(self, to, packet.js); // use the given ipp override since new connects happen from restarts
}

// be the middleman to help NAT hole punch
function inPeer(self, packet)
{
  if(!Array.isArray(packet.js.peer) || packet.js.peer.length == 0) return warn("invalid peer of", packet.js.peer, "from", packet.from.address);

  packet.js.peer.forEach(function(hn){
    var peer = seen(self, hn);
    if(!peer.lineIn) return; // these happen often as lines come/go, ignore dead peer requests
    var js = {ip:packet.from.ip, port:packet.from.port};
    if(packet.js.local && packet.js.local.ip != packet.from.ip) js.local = packet.js.local; // relay any optional local information
    addStream(self, peer, "connect").send(js, packet.from.pubkey);
  });
}

// return array of nearby hashname objects
function nearby(self, hash)
{
  var ret = {};
  
  // return up to 5 closest, in the same or higher (further) bucket
  var bucket = self.hash.distanceTo(new dhash.Hash(null, hash));
  while(bucket <= 255 && Object.keys(ret).length < 5)
  {
    if(self.buckets[bucket]) self.buckets[bucket].forEach(function(hn){
      if(!hn.lineIn) return; // only see ones we have a line with
      ret[hn.hashname] = hn;
    });
    bucket++;
  }

  // use any if still not full
  if(Object.keys(ret).length < 5) Object.keys(self.lines).forEach(function(line){
    if(Object.keys(ret).length >= 5) return;
    ret[self.lines[line].hashname] = self.lines[line];
  });
  var reta = [];
  Object.keys(ret).forEach(function(hn){
    reta.push(ret[hn]);
  });
  return reta;
}

// return a see to anyone closer
function inSeek(self, packet)
{
  if(!dhash.isHEX(packet.js.seek, 64)) return warn("invalid seek of ", packet.js.seek, "from:", packet.from.address);

  // now see if we have anyone to recommend
  var answer = {see:nearby(self, packet.js.seek).map(function(hn){ return hn.address; }), end:true};  
  packet.stream.send(answer);
}
