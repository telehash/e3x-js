(function(exports){ // browser||node safe wrapper

var warn = function(a,b,c,d,e,f){console.log(a,b,c,d,e,f); return undefined; };
var debug = function(a,b,c,d,e,f){console.log(a,b,c,d,e,f)};

var defaults = exports.defaults = {};
defaults.chan_timeout = 10000; // 10 seconds for channels w/ no acks
defaults.seek_timeout = 3000; // shorter tolerance for seeks, is far more lossy

// dependency functions
var local;
exports.localize = function(locals){ local = locals; }

// start a hashname listening and ready to go
exports.hashname = function(key, send, args)
{
  if(!local) return warn("thjs.locals() needs to be called first");
  if(!key || !key.public || !key.private) return warn("bad args to hashname, requires key.public and key.private");
  if(typeof send !== "function") return warn("second arg needs to be a function to send packets, is", typeof send);

  // configure defaults
  if(!args) args = {};
  var self = {seeds:[], lines:{}, all:{}, buckets:[], listening:{}};
  self.private = key.private;
  self.public = key.public;
  self.der = local.key2der(self.public);
  self.hashname = local.der2hn(self.der);
  self.nat = true;
  if(args.family) self.family = args.family;
  if(args.ip) self.ip = args.ip;
  if(args.port) self.port = args.port;

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
  - callback(arg, chan)
    - called for any incoming channel start
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
exports.channelSetups = {
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
  self.listening[type] = function(packet, chan){
    packet.js = packet.js["_"];
    callback(packet, chan);
  };
}

function addSeed(arg) {
  var self = this;
  if(!arg.ip || !arg.port || !arg.pubkey) return warn("invalid args to addSeed");
  var der = local.key2der(arg.pubkey);
  var seed = self.whois(local.der2hn(der));
  seed.der = der;
  seed.ip = arg.ip;
  seed.port = parseInt(arg.port);
  self.seeds.push(seed);
}

function online(callback)
{
	var self = this;
  var dones = self.seeds.length;
  if(!dones) return callback("no seeds");
  // safely callback only once or when all seeds failed
  function done(err)
  {
    if(!dones) return; // already called back
    // success!
    if(!err)
    {
      callback();
      dones = 0;
    }
    dones--;
    // failed
    if(!dones) callback(err);
  }
	self.seeds.forEach(function(seed){
    seed.seek(self.hashname, function(err, see){
      if(Array.isArray(see)) see.forEach(function(item){
        var parts = item.split(",");
        if(parts.length != 3) return;
        if(parts[0] !== self.hashname) return;
        // update our known public IP/Port
        self.pubip = parts[1];
        self.pubport = parseInt(parts[2]);
        // detect when not NAT'd
        if(self.ip == self.pubip && self.port == self.pubport) self.nat = false;
      })
      done(err);
    })
	})
}

// self.receive, raw incoming udp data
function receive(msg, from)
{
	var self = this;
  var packet = local.pdecode(msg);
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
    var open = local.deopenize(self, packet);
    if (!open) return warn("couldn't decode open");
    var from = self.whois(local.der2hn(open.rsa));
    if (!from) return warn("invalid hashname", local.der2hn(open.rsa), open.rsa);

    // make sure this open is newer (if any others)
    if (typeof open.js.at != "number" || (from.openAt && open.js.at < from.openAt)) return warn("invalid at", open.js.at);

    // update values
    var line = {};
    debug("inOpen verified", from.hashname, open);
    from.openAt = open.js.at;
    from.der = open.rsa;
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
    if (!from.sentOpen) from.open();

    // line is open now!
    local.openline(from, open);
    
    // replace function to send things via the line
    from.send = function(packet) {
      debug("line sending",from.hashname, packet.js);
      // TODO if line hasn't responded, break it and start over
      self.send(from, local.lineize(from, packet));
      // TODO if ended, set timer to cleanup
    }
    
    // handle first incoming packets
    from.receive = function(packet)
    {
      from.recvAt = Date.now();
      if(!packet.js || !isHEX(packet.js.c, 32)) return warn("dropping invalid channel packet");
      var chan = from.chans[packet.js.c];
      if(chan)
      {
        chan.receive(packet);
        // TODO if ended, set timer to cleanup
        return;
      }
      // start a channel if one doesn't exist
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
      var chan;
      // make a channel for any that need to exist yet beyond this
      if(!packet.js.end)
      {
        chan = from.channel(packet.js.type, packet.js.c);
        chan.inDone = chan.inHandled = 0; // since we need to .ack this first start packet
      }
      debug("channel listening",from.hashname, packet.js.type, packet.js);
      self.listening[packet.js.type](packet, chan, self);
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
	  local.delineize(packet);
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
  if(!isHEX(hashname, 64)) { warn("whois called without a valid hashname", hashname); return false; }

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
      packet.js = packet.js["_"];
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
    if(hn.der && hn.ip && hn.port) return hn.open();

    // if any via information, try them all! (usually only one)
    if(hn.vias)
    {
      Object.keys(hn.vias).forEach(function(via){
        var address = hn.vias[via].split(",");
        var to = {ip:address[1],port:address[2]};
        self.send(to,local.pencode().bytes()); // NAT hole punching
        self.whois(via).peer(hn.hashname); // send the peer request
      });
      delete hn.vias; // so next time it'll re-seek
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

  // send a simple lossy peer request, don't care about answer
  hn.peer = function(hashname, ip)
  {
    var chan = this.channel("peer");
    var js = {"peer":hashname};
    // if on the same NAT'd IP, also relay our local IPP
    if(self.nat && self.ip && ip == self.pubip) js.local = {ip:self.ip, port:self.port};
    chan.ack(true, {js:js});
  }
  
  // just send an open packet, direct overrides the ipp of to
  hn.open = function(direct)
  {
    hn.sentOpen = true;
    var open = local.openize(self, hn);
    self.lines[hn.lineOut] = hn;
    self.send(direct||hn, open);
    // when we have a local alternate address, try that too
    if(hn.local) self.send(hn.local, open);
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
	if(!id) id = local.randomHEX(16);
  var chan = {inq:[], outq:[], outSeq:0, inDone:-1, outConfirmed:0, inDups:0, lastAck:-1, type:type, id:id};
	hn.chans[id] = chan;
  // set flag for app types
  if(type.substr(0,1) == "_")
  {
    chan.app = true;
    chan.type = type.substr(1); // for the app
  }
  chan.hashname = hn.hashname; // for convenience

  debug("new channel",hn.hashname,chan.type);
  // used by app to change how it interfaces with the channel
  chan.setup = function(setup)
  {
    var chan = this;
    if(!exports.channelSetups[setup]) return false;
    exports.channelSetups[setup](chan);
    return chan;
  }

  // used by anyone to end the channel
  chan.end = function(err){chan.ack(err||true)};

	// process packets at a raw level, handle all miss/ack tracking and ordering
	chan.receive = function(packet)
	{
    console.log("LINEIN",chan.type,JSON.stringify(packet.js));
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
	    var outq = chan.outq;
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
    console.log("SEND",chan.type,JSON.stringify(packet.js));
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
    if(chan.app) packet.js = {"_":packet.js};
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
  var der = local.der2der(packet.body);
  var to = self.whois(local.der2hn(der));
  if(!to || !packet.js.ip || typeof packet.js.port != 'number') return warn("invalid connect request from",packet.from.address,packet.js);
  // if no ipp yet, save them
  if(!to.ip) {
    to.ip = packet.js.ip;
    to.port = parseInt(packet.js.port);
  }
  // if possible NAT-local given, cache that for the open flow too
  if(self.nat && packet.js.local && typeof packet.js.local.ip == "string" && typeof packet.js.local.port == "number" && packet.js.local.ip != to.ip) to.local = packet.js.local;
  if(to.sentOpen)
  {
    // don't resend to fast to prevent abuse/amplification
    if(to.resentOpen && (Date.now() - to.resentOpen) < 5000) return warn("told to connect too fast, ignoring from",packet.from.address,"to",to.address, Date.now() - to.resentOpen);
    to.resentOpen = Date.now();
    to.sentOpen = false;
  }else{
    to.der = der;
  }
  to.open(packet.js); // use the given ipp override since new connects happen from restarts
}

// be the middleman to help NAT hole punch
function inPeer(packet, chan, self)
{
  if(!isHEX(packet.js.peer, 64)) return warn("invalid peer of", packet.js.peer, "from", packet.from.address);

  var peer = self.whois(packet.js.peer);
  if(!peer.lineIn) return; // these happen often as lines come/go, ignore dead peer requests
  var js = {ip:packet.from.ip, port:packet.from.port};
  if(packet.js.local && packet.js.local.ip != packet.from.ip) js.local = packet.js.local; // relay any optional local information
  var chan = peer.channel("connect");
  chan.ack(true, {js:js, body:packet.from.der});
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
  if(!isHEX(packet.js.seek, 64)) return warn("invalid seek of ", packet.js.seek, "from:", packet.from.address);

  // now see if we have anyone to recommend
  var answer = {see:self.nearby(packet.js.seek).map(function(hn){ return hn.address; })};  
  chan.ack(true, {js:answer});
}

// utility functions

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
  for (var i = 0; i < hex.length / 2; i ++) {
      var bite = parseInt(hex.substr(i * 2, 2), 16);
      if (isNaN(bite)) return [];
      ret[ret.length] = bite >> 4;
      ret[ret.length] = bite & 0xf;
  }
  return ret;
}


// our browser||node safe wrapper
})(typeof exports === 'undefined'? this['thjs']={}: exports);