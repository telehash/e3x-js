var warn = function(a,b,c,d,e,f){console.log(a,b,c,d,e,f)};
var debug = function(a,b,c,d,e,f){console.log(a,b,c,d,e,f)};

var defaults = {};
defaults.chan_timeout = 10000; // 10 seconds for channels w/ no acks
defaults.seek_timeout = 3000; // shorter tolerance for seeks, is far more lossy

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
  var self = {seeds:[], lines:{}, all:{}, buckets:[], listening:{}};
  self.private = key.private;
  self.public = key.public;
  self.hashname = key2hn(self.public);
	self.der = asn1.toDer(pki.publicKeyToAsn1(self.public)).bytes();
  self.nat = true;
  if(args.family) self.family = args.family;

  // udp socket stuff
  self.pcounter = 1;
  self.receive = receive;
	self.send = send; // external sending function passed in
  
  // need some seeds to connect to, addSeed({ip:"1.2.3.4", port:5678, public:"PEM"})
  self.addSeed = addSeed;
	
	// map a hashname to an object, whois(hashname)
	self.whois = whois;
  
  // connect to the network, online(callback(err))
  self.online = online;

  // handle new channels coming in from anyone
  self.start = start;
  
	// internal listening builtins
	self.listening["peer"] = inPeer;
	self.listening["connect"] = inConnect;
	self.listening["seek"] = inSeek;

  // primarily internal, to seek/connect to a hashname
  self.seek = seek;
  
  // return array of closest known hashname objects
  self.nearby = nearby;

  return self;
}

/* CHANNELS
hn.start(type, arg, callback)
  - used by app to create a channel of given type
  - arg contains .js and .body for the first packet
  - callback(err, arg, chan)
    - called when a response is received (or error/fail)
    - given the response .js .body in arg
    - chan.setup(bulk|message|stream|packet)
    - chan.bulk(str, cbDone) / onBulk(cbDone(err, str))
    - chan.message() / .onMessage
    - chan.read/write
    - chan.packet, onPacket
self.start(type, callback)
  - used to listen for incoming channel starts
  - callback(arg, cbStarted)
    - called for any incoming channel start
    - to answer, call cbStarted(err, arg), returns chan
    - chan.setup and chan.* from above

// internally
chan.ack() sends a packet reliably using line.send(), escapes .js for app
chan.receive() 
  - receives a packet reliably
  - unescapes .js for app
  - calls .handle() in order
  - sets timer for autoack
*/

// these are called once a channel is started both ways to add type-specific functions for the app
var channelSetups = {
	"packet":function(chan){
    // to send raw packets
    chan.packet = function(packet)
    {
      // catch any end packets just in case, so we know it ended
      if(packet.js && packet.js.end) return chan.ack(packet);
      chan.send(packet); // send it raw
    }
    // friendly wrapper, calls chan.onPacket(err, packet)
    chan.receive = function(packet){
      if(!chan.onPacket) return chan.end("no handler");
      if(packet.js.end) chan.ended = true;
      chan.onPacket(packet.js.err||packet.js.end, packet);
    }
	},
	"message":function(chan){
    // to send new messages
    chan.message = function(arg, cbConfirm){
      arg.callback = cbConfirm;
      chan.ack(false, arg);
    };
    // calls chan.onMessage(err, {js:, body:})
    chan.handle = function(packet, callback){
      if(!chan.onMessage) return chan.end("no handler");
      if(packet.js.end) return chan.onMessage(packet.js.err||packet.js.end);
      chan.onMessage(false, {js:packet.js["_"], body:packet.body, chan:chan}, callback);
    };
	},
	"stream":function(chan){
    // send raw data over, must not be called again until cbMore(err) is called
    chan.write = function(data, cbMore)
    {
      // break data into chunks
      // if outgoing is full, chan.more = cbMore
    }
    chan.handle = function(packet, callback)
    {
      if(!chan.read) return chan.end("no handler");
      // TODO if chan.more and outgoing isn't full, var more=chan.more;delete chan.more;more()
      if(!packet.body && !packet.js.end) return callback(); // odd empty?
      chan.read(packet.js.err||packet.js.end, packet.body, callback);
    }
	},
	"bulk":function(chan){
    // handle any incoming bulk flow
    var bulkIn = "";
    chan.handle = function(packet, callback)
    {
      if(packet.js.body) bulkIn += packet.js.body;
      if(packet.js.end && chan.onBulk) chan.onBulk(packet.js.err||packet.js.end, bulkIn);
    }
    // handle (optional) outgoing bulk flow
    chan.bulk = function(data, callback)
    {
      // TODO break arg.bulk into chunks and send out using chan.ack()      
    }
	}
}

// this is self.start, for the app "listening" for any incoming channel type
function start(type, callback)
{
  var self = this;
  if(type.substr(0,1) != "_") type = "_"+type;
  self.listens[type] = function(packet, chan){
    packet.js = packet.js["_"];
    callback(packet, chan);
  };
}

function addSeed(arg) {
  var self = this;
  if(arg) arg.public = pki.publicKeyFromPem(arg.pubkey);
  if(!arg.ip || !arg.port || !arg.public) return warn("invalid args to addSeed");
  var seed = self.whois(key2hn(arg.public));
  seed.public = arg.public;
  seed.ip = arg.ip;
  seed.port = parseInt(arg.port);
  self.seeds.push(seed);
}

function online(callback)
{
	var self = this;
	self.onlineCB = callback;
	self.seeds.forEach(function(seed){
		sendOpen(self, seed);
	})
}

// self.receive, raw incoming udp data
function receive(msg, from)
{
	var self = this;
  var packet = pdecode(msg);
  if(!packet) return warn("failed to decode a packet from", from.ip, from.port, msg.toString());
  if(Object.keys(packet.js).length == 0) return; // empty packets are NAT pings
  if(typeof packet.js.iv != "string" || packet.js.iv.length != 32) return warn("missing initialization vector (iv)", packet.sender);

  packet.sender = {ip:from.ip, port:from.port};
  packet.id = self.pcounter++;
  packet.at = Date.now();
  debug("in",packet.sender.ip+":"+packet.sender.port, packet.js.type, packet.body && packet.body.length);

  // either it's an open
  if(packet.js.type == "open")
	{
    var open = deopenize(self, packet);
    if (!open) return warn("couldn't decode open");
    var from = self.whois(key2hn(open.rsa));
    if (!from) return warn("invalid hashname", key2hn(open.rsa), open.rsa);

    // make sure this open is newer (if any others)
    if (typeof open.js.at != "number" || (from.openAt && open.js.at < from.openAt)) return warn("invalid at", open.js.at);

    // update values
    var line = {};
    debug("inOpen verified", from.hashname, open);
    from.openAt = open.js.at;
    from.public = open.rsa;
    from.ip = packet.sender.ip;
    from.port = packet.sender.port;
    from.address = [from.hashname, from.ip, from.port].join(",");
    from.recvAt = Date.now();

    // was an existing line already, being replaced
    if (from.lineIn && from.lineIn !== open.js.line) {
      debug("changing lines", from.hashname);
      from.sentOpen = false; // trigger resending them our open again
    }
    from.lineIn = open.js.line;

    // do we need to send them an open yet?
    if (!from.sentOpen) sendOpen(self, from);

    // line is open now!
    openline(from, open);
    
    // replace function to send things via the line
    from.send = function(packet) {
      // TODO if line hasn't responded, break it and start over
      self.send(from, lineize(from, packet));
      // TODO if ended, set timer to cleanup
    }
    
    // handle first incoming packets
    from.receive = function(packet)
    {
      from.recvAt = Date.now();
      if(!packet.js || !isHEX(packet.js.c, 32)) return warn("dropping invalid channel packet");
      var chan = from.chans[packet.js.c];
      // start a channel if one doesn't exist
      if(!chan)
      {
        if(packet.js.seq !== 0) return; // only handle first/start packets
        if(!self.listening[packet.js.type])
        {
          // bounce error
          if(!packet.js.end)
          {
            packet.js.end = true;
            packet.js.error = "unknown type";
            warn("bouncing unknown channel/type",packet.js);
            from.send(packet);            
          }
          return;
        }
        chan = from.channel(packet.js.type, packet.js.c);
        chan.inHandled = 0; // so we .ack this first start packet
        return self.listening[packet.js.type](packet, chan, self);
      }
      chan.receive(packet);
      // TODO if ended, set timer to cleanup
    }

    // if anyone was waiting for a trigger
    if (from.onLine) {
      from.onLine();
      delete from.onLine;
    }
    return;
	}

  // or it's a line
  if(packet.js.type == "line")
	{
	  var line = packet.from = self.lines[packet.js.line];

	  // a matching line is required to decode the packet
	  if(!line) return debug("unknown line received", packet.js.line, packet.sender);

		// decrypt and process
	  delineize(packet);
		if(!packet.lineok) return debug("couldn't decrypt line",packet.sender);
		line.receive(packet);
    return;
	}
  
  if(Object.keys(packet.js).length > 0) warn("dropping incoming packet of unknown type", packet.js, packet.sender);
}

function whois(hashname)
{
  var self = this;
  // validations
  if(!hashname) { warn("whois called without a hashname", hashname); return false; }
  if(typeof hashname != "string") { warn("wrong type, should be string", typeof hashname,hashname); return false; }
  hashname = hashname.split(",")[0]; // convenience if an address is passed in
  if(!isHEX(hashname, 64)) { warn("seen called without a valid hashname", hashname); return false; }

  // so we can check === self
  if(hashname === self.hashname) return self;

  var hn = self.all[hashname];
	if(hn) return hn;
  hn = self.all[hashname] = {hashname:hashname, chans:{}};
  hn.at = Date.now();

  // internal, to create a new channel
  hn.channel = channel;

	// app convenience wrapper to start a new channel to this hashname
  hn.start = function(type, arg, callback)
  {
    if(type.substr(0,1) != "_") type = "_"+type;
    var chan = hn.channel(type);
    chan.ack(false, arg);
    // feed the first answer back to the app
    chan.handle = function(packet, cbHandle)
    {
      var ended = packet.js.err||packet.js.end;
      if(ended)
      {
        chan.ended = true;
        callback(ended, packet);
        return cbHandle();
      }
      // the app should call chan.setup() that reconfigures chan.handle
      callback(false, packet, chan);
      cbHandle();
    }
  }
  
  // internal, trying to send on a line needs to create it first
  // this function gets replaced as soon as there's a line created
  hn.send = function(packet){
    // try to re-send the packet as soon as there's a line
    hn.onLine = function(){ hn.send(packet) }

    // if any pub key and ip/port, try that
    if(hn.public && hn.ip && hn.port) return hn.open();

    // if any via information, try them
    if(hn.vias)
    {
      Object.keys(hn.vias).forEach(function(via){
        var address = hn.vias[via].split(",");
        var to = {ip:address[1],port:address[2]};
        self.send(to,pencode().bytes()); // NAT hole punching
        self.whois(via).peer()
// HERE        
        
      });
      return;
    }

    // need to find new/updated connectivity info
    if(packet.seeked) return; // don't try to seek more than once
    packet.seeked = true;
    self.seek(hn, function(err){
      if(err)
      {
        // TODO end all channels with this error
        return;
      }
      // recurse back into ourselves to try connecting
      hn.send(packet);
    });
  }

  // track who told us about this hn
  hn.via = function(from, address)
  {
    if(!hn.vias) hn.vias = {};
    if(hn.vias[from.hashname]) return;
    hn.vias[from.hashname] = address; // TODO handle multiple addresses per hn (ipv4+ipv6)
  }
  
  // just make a seek request conveniently
  hn.seek = function(hashname, callback)
  {
    var chan = this.channel("seek");
    chan.ack(false, {js:{"seek":hashname}});
    chan.receive = function(packet){
      callback(packet.js.err,Array.isArray(packet.js.see)?packet.js.see:[]);
    }
  }
  
  // just send an open packet, direct overrides the ipp of to
  hn.open = function(direct)
  {
    hn.sentOpen = true;
    var open = openize(self, hn);
    self.lines[hn.lineOut] = hn;
    self.send(direct||hn, open);
  }
  
  return hn;
}

// seek the dht for this hashname
function seek(hn, callback)
{
  var self = this;
  if(typeof hn == "string") hn = self.whois(hn);
  if(hn.lineOut || hn === self) return callback();
  var done = false;
  var did = {};
  var doing = {};
  var queue = [];
  var closest = 255;
  self.nearby(hn.hashname).forEach(function(near){
    if(queue.indexOf(near.hashname) == -1) queue.push(near.hashname);
  });
  // always process potentials in order
  function sort()
  {
    queue.sort(function(a,b){dhash(hn.hashname,a) - dhash(hn.hashname,b)});    
  }
  sort();

  // main loop, multiples of these running at the same time
  function loop(){
    if(done) return;
    console.log("SEEK LOOP",queue);
    // if nothing left to do and nobody's doing anything, failed :(
    if(Object.keys(doing).length == 0 && queue.length == 0)
    {
      done = true;
      callback("failed to find the hashname");
      return;
    }
    
    // get the next one to ask
    var mine = queue.shift();
    if(!mine) return; // another loop() is still running

    // if we found it, yay! :)
    if(mine == hn.hashname)
    {
      done = true;
      callback();
      return;
    }
    // skip dups
    if(did[mine] || doing[mine]) return loop();
    var distance = dhash(hn.hashname, mine);
    if(distance > closest) return loop(); // don't "back up" further away
    closest = distance;
    doing[mine] = true;
    var to = self.whois(mine);
    to.seek(hn.hashname, function(err, see){
      see.forEach(function(item){
        var sug = self.whois(item);
        if(sug === self) return; // happens
        if(!sug) return warn("bad see",item,to.hashname);
        sug.via(to, item);
        queue.push(sug.hashname);
      });
      sort();
      did[mine] = true;
      delete doing[mine];
      loop();
    });
  }
  
  // start three of them
  loop();loop();loop();
}

function channel(type, id)
{
  var hn = this;
	if(!id) id = randomHEX(16);
  var chan = {inq:[], outq:[], outSeq:0, inDone:-1, outConfirmed:0, inDups:0, lastAck:-1, type:type, id:id};
	hn.chans[id] = chan;
  // set flag for app types
  if(type.substr(0,1) == "_")
  {
    chan.app = true;
    chan.type = type.substr(1); // for the app
  }
  chan.hashname = hn.hashname; // for convenience

  // used by app to change how it interfaces with the channel
  chan.setup = function(setup)
  {
    var chan = this;
    if(!channelSetups[setup]) return false;
    channelSetups[setup](chan);
    return chan;
  }

  // used by anyone to end the channel
  chan.end = function(err){chan.ack(err||true)};

	// process packets at a raw level, handle all miss/ack tracking and ordering
	chan.receive = function(packet)
	{
	  if(!(packet.js.seq >= 0)) return warn("invalid sequence on stream", packet.js.seq, chan.id, packet.from.address);

	  // so, if there's a lot of "gap" or or dups coming in, be kind and send an update immediately
	  if(packet.js.seq - chan.outConfirmed > 30 || chan.inDups) chan.ack();

	  // track and drop duplicate packets
	  if(packet.js.seq <= chan.inDone || chan.inq[packet.js.seq - (chan.inDone+1)]) return chan.inDups++;

	  // process any valid newer incoming ack/miss
	  var ack = parseInt(packet.js.ack);
	  var miss = Array.isArray(packet.js.miss) ? packet.js.miss : [];
	  if(miss.length > 100) return warn("too many misses", miss.length, chan.id, packet.from.address);
	//console.log(">>>ACK", ack, chan.lastAck, chan.outSeq, "len", chan.outq.length, chan.outq.map(function(p){return p.js.seq}).join(","));
	  if(ack > chan.lastAck && ack <= chan.outSeq)
	  {
	    chan.lastAck = ack;
	    // rebuild outq, only keeping missed/newer packets
	    var outq = stream.outq;
	    chan.outq = [];
	    outq.forEach(function(pold){
	      // packet acknowleged!
	      if(pold.js.seq <= ack && miss.indexOf(pold.js.seq) == -1) {
	        if(pold.callback) pold.callback();
	        return;
	      }
	      chan.outq.push(pold);
	      if(miss.indexOf(pold.js.seq) == -1) return;
	      // resend misses but not too frequently
	      if(Date.now() - pold.resentAt < 5*1000) return;
	      pold.resentAt = Date.now();
	      hn.send(pold);
	    });
	  }
  
	  // drop out of bounds
	  if(packet.js.seq - chan.inDone > 100) return warn("chan too far behind, dropping", chan.id, packet.from.address);

	  // stash this seq and process any in sequence
	  packet.chan = chan;
	  chan.inq[packet.js.seq - (chan.inDone+1)] = packet;
    if(chan.inq[0]) chan.handler();
    
	  while(chan.inq[0])
	  {
	    packet = chan.inq.shift();
	    chan.inDone++;
	    // sends them to the async queue that calls inchanSeries()
	    chan.q.push(packet);
	  }
	}
  
  // wrapper to call chan.handle in series
  chan.handler = function()
  {
    if(!chan.handle) return warn("no chan.handle() function setup?");
    if(chan.handling) return;
    chan.handling = true;
    var packet = chan.inq.shift();
    chan.inDone++;
    chan.handle(packet, function(){
      chan.inHandled = packet.js.seq;
      chan.handling = false;
      if(chan.inq[0]) chan.handler();
    })
  }
  
  // minimal wrapper to send raw packets
  chan.send = function(packet)
  {
	  // force type on the first outgoing packet (not in answer)
    if(packet.js.seq == 0 && packet.js.ack == undefined) packet.js.type = (chan.app?"_":"")+chan.type;
    // make sure to save/set ended
    if(packet.js.end) chan.ended = packet;      
    packet.js.c = chan.id;
    hn.send(packet);
  }
	
	chan.ack = function(end, arg)
	{
    if(chan.ended) return warn("can't send to an ended channel");

	  // these are just empty "ack" requests, drop if no reason to ack so they're harmless
	  if(!end && !arg && chan.outConfirmed == chan.inHandled && !chan.inDups) return;

    // create the packet
    if(!arg) arg = {};
    var packet = {};
    packet.js = arg.js || {};
    // do any app js escaping and set type if needed
    if(chan.app) packet.js["_"] = packet.js;
    packet.body = arg.body;
    packet.callback = arg.callback;

    if(end)
    {
      packet.js.end = true;
      if(end !== true) packet.js.err = end;
      if(packet.callback) packet.callback("can't confirm end packet")
    }

    // do durable stuff
	  packet.js.seq = chan.outSeq++;
	  if(chan.inHandled >= 0) packet.js.ack = chan.inHandled; // confirm only what's been processed

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
	  chan.outConfirmed = packet.js.ack;
	  chan.inDups = 0;
    chan.outq.push(packet);
    chan.send(packet);
    return chan;
	}

  return chan;		
}

// someone's trying to connect to us, send an open to them
function inConnect(packet, chan, self)
{
  var to = self.whois(key2hash(packet.body).toString());
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
function inPeer(packet, chan, self)
{
  if(!Array.isArray(packet.js.peer) || packet.js.peer.length == 0) return warn("invalid peer of", packet.js.peer, "from", packet.from.address);

  packet.js.peer.forEach(function(hn){
    var peer = self.whois(hn);
    if(!peer.lineIn) return; // these happen often as lines come/go, ignore dead peer requests
    var js = {ip:packet.from.ip, port:packet.from.port};
    if(packet.js.local && packet.js.local.ip != packet.from.ip) js.local = packet.js.local; // relay any optional local information
    addStream(self, peer, "connect").send(js, packet.from.pubkey);
  });
}

// return array of nearby hashname objects
function nearby(hashname)
{
  var self = this;
  var ret = {};
  
  // return up to 5 closest, in the same or higher (further) bucket
  var bucket = dhash(self.hashname, hashname);
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
function inSeek(packet, chan, self)
{
  if(!dhash.isHEX(packet.js.seek, 64)) return warn("invalid seek of ", packet.js.seek, "from:", packet.from.address);

  // now see if we have anyone to recommend
  var answer = {see:nearby(self, packet.js.seek).map(function(hn){ return hn.address; }), end:true};  
  packet.stream.send(answer);
}
