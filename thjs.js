(function(exports){ // browser||node safe wrapper

var warn = function(){console.log.apply(console,arguments); return undefined; };
var debug = function(){};
//var debug = function(){console.log.apply(console,arguments)};
exports.debug = function(cb){ debug = cb; };


var defaults = exports.defaults = {};
defaults.chan_timeout = 10000; // how long before for ending durable channels w/ no acks
defaults.seek_timeout = 3000; // shorter tolerance for seeks, is far more lossy
defaults.chan_autoack = 1000; // is how often we auto ack if the app isn't generating responses in a durable channel
defaults.chan_resend = 2000; // resend the last packet after this long if it wasn't acked in a durable channel
defaults.chan_outbuf = 100; // max size of outgoing buffer before applying backpressure
defaults.chan_inbuf = 50; // how many incoming packets to cache during processing/misses

// dependency functions
var local;
exports.localize = function(locals){ local = locals; }

exports.isHashname = function(hex)
{
  return isHEX(hex, 64);
}

// start a hashname listening and ready to go
exports.hashname = function(key, send, args)
{
  if(!local) return warn("thjs.localize() needs to be called first");
  if(!key || !key.public || !key.private) return warn("bad args to hashname, requires key.public and key.private");
  if(!local.pub2key(key.public) || !local.pri2key(key.private)) return warn("key.public and key.private must be valid pem strings");
  if(typeof send !== "function") return warn("second arg needs to be a function to send packets, is", typeof send);

  // configure defaults
  if(!args) args = {};
  var self = {seeds:[], lines:{}, all:{}, buckets:[], rels:{}, raws:{}};
  self.private = local.pri2key(key.private);
  self.public = local.pub2key(key.public);
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

  // handle new reliable channels coming in from anyone
  self.listen = function(type, callback){
    if(type.substr(0,1) !== "_") type = "_"+type;
    self.rels[type] = callback;
  };
  // advanced usage only
  self.raw = function(type, callback){
    self.raws[type] = callback;
  };
  
	// internal listening unreliable channels
	self.raws["peer"] = inPeer;
	self.raws["connect"] = inConnect;
	self.raws["seek"] = inSeek;

  // primarily internal, to seek/connect to a hashname
  self.seek = seek;
  
  // return array of closest known hashname objects
  self.nearby = nearby;

  return self;
}

/* CHANNELS API
hn.channel(type, arg, callback)
  - used by app to create a reliable channel of given type
  - arg contains .js and .body for the first packet
  - callback(err, arg, chan, cbDone)
    - called when any packet is received (or error/fail)
    - given the response .js .body in arg
    - cbDone when arg is processed
    - chan.send() to send packets
    - chan.wrap(bulk|stream) to modify interface, replaces this callback handler
      - chan.bulk(str, cbDone) / onBulk(cbDone(err, str))
      - chan.read/write
hn.raw(type, arg, callback)
  - arg contains .js and .body to create an unreliable channel 
  - callback(err, arg, chan)
    - called on any packet or error
    - given the response .js .body in arg
    - chan.send() to send packets

self.channel(type, callback)
  - used to listen for incoming reliable channel starts
  - callback(err, arg, chan, cbDone)
    - called for any answer or subsequent packets
    - chan.wrap() to modify
self.raw(type, callback)
  - used to listen for incoming unreliable channel starts
  - callback(err, arg, chan)
    - called for any incoming packets
*/

// these are called once a reliable channel is started both ways to add custom functions for the app
exports.channelWraps = {
	"stream":function(chan){
    // send raw data over, must not be called again until cbMore(err) is called
    chan.write = function(data, cbMore)
    {
      // break data into chunks
      // if outgoing is full, chan.more = cbMore
    }
    chan.callback = function(packet, callback)
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
    chan.callback = function(packet, callback)
    {
      if(packet.js.body) bulkIn += packet.js.body;
      if(packet.js.end && chan.onBulk) chan.onBulk(packet.js.err||packet.js.end, bulkIn);
    }
    // handle (optional) outgoing bulk flow
    chan.bulk = function(data, callback)
    {
      // TODO break arg.bulk into chunks and send out using chan.push()      
    }
	}
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
    if (!open || !open.verify) return warn("couldn't decode open",open);
    if (!isHEX(open.js.line, 32)) return warn("invalid line id enclosed",open.js.line);
    if(open.js.to !== self.hashname) return warn("open for wrong hashname",open.js.to);

    var from = self.whois(local.der2hn(open.rsa));
    if (!from) return warn("invalid hashname", local.der2hn(open.rsa), open.rsa);

    // make sure this open is newer (if any others)
    if (typeof open.js.at != "number" || (from.openAt && open.js.at < from.openAt)) return warn("invalid at", open.js.at);

    // update values
    var line = {};
    debug("inOpen verified", from.hashname);
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
    }
    
    // handle all incoming line packets
    from.receive = function(packet)
    {
//      if((Math.floor(Math.random()*10) == 4)) return warn("testing dropping randomly!");
      from.recvAt = Date.now();
      if(!packet.js || !isHEX(packet.js.c, 32)) return warn("dropping invalid channel packet");

      debug("LINEIN",JSON.stringify(packet.js));

      // find any existing channel
      var chan = from.chans[packet.js.c];
      if(chan) return chan.receive(packet);

      // start a channel if one doesn't exist, check either reliable or unreliable types
      var listening = {};
      if(typeof packet.js.seq == "undefined") listening = self.raws;
      if(packet.js.seq === 0) listening = self.rels;
      if(!listening[packet.js.type])
      {
        // bounce error
        if(!packet.js.end && !packet.js.err)
        {
          warn("bouncing unknown channel/type",packet.js);
          var err = (packet.js.type) ? "unknown type" : "unknown channel"
          from.send({js:{err:err,c:packet.js.c}});
        }
        return;
      }
      // make the correct kind of channel;
      var kind = (listening == self.raws) ? "raw" : "start";
      var chan = from[kind](packet.js.type, {id:packet.js.c}, listening[packet.js.type]);
      chan.receive(packet);
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
  hn = self.all[hashname] = {hashname:hashname, chans:{}, self:self};
  hn.at = Date.now();

  // to create a new channels to this hashname
  hn.start = channel;
  hn.raw = raw;

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
        self.send(to,local.pencode()); // NAT hole punching
        self.whois(via).peer(hn.hashname); // send the peer request
      });
      // so next time it'll re-seek
      delete hn.vias;
      delete packet.seeked;
      return;
    }

    // need to find new/updated connectivity info
    if(packet.seeked) return; // don't try to seek more than once
    packet.seeked = true;
    self.seek(hn, function(err){
      if(err)
      {
        Object.keys(hn.chans).forEach(function(cid){
          hn.chans[cid].fail({js:{err:err}});
        });
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
    var tries = 0;
    function seek()
    {
      tries++;
      if(tries > 3) return callback("timed out", []);
      var timer = setTimeout(seek, 1000);
      hn.raw("seek", {js:{"seek":hashname}}, function(err, packet, chan){
        if(tries > 3) return; // already failed back
        clearTimeout(timer);
        callback(packet.js.err,Array.isArray(packet.js.see)?packet.js.see:[]);
      });
    }
    seek();
  }

  // send a simple lossy peer request, don't care about answer
  hn.peer = function(hashname, ip)
  {
    var js = {type:"peer", end:true, "peer":hashname, c:local.randomHEX(16)};
    // if on the same NAT'd IP, also relay our local IPP
    if(self.nat && self.ip && ip == self.pubip) js.local = {ip:self.ip, port:self.port};
    hn.send({js:js});
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
    debug("SEEK LOOP",queue);
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

// create an unreliable channel
function raw(type, arg, callback)
{
  var hn = this;
  var chan = {type:type, callback:callback};
  chan.id = arg.id || local.randomHEX(16);
	hn.chans[chan.id] = chan;

  chan.hashname = hn.hashname; // for convenience

  debug("new unreliable channel",hn.hashname,chan.type);

	// process packets at a raw level, handle all miss/ack tracking and ordering
	chan.receive = function(packet)
	{
    // if err'd or ended, delete ourselves
    if(packet.js.err || packet.js.end) delete hn.chans[chan.id];
    chan.callback(packet.js.err||packet.js.end, packet, chan);
  }

  // minimal wrapper to send raw packets
  chan.send = function(packet)
  {
    packet.js.c = chan.id;
    debug("SEND",chan.type,JSON.stringify(packet.js));
    hn.send(packet);
    // if err'd or ended, delete ourselves
    if(packet.js.err || packet.js.end) delete hn.chans[chan.id];
  }

  // send optional initial packet with type set
  if(arg.js)
  {
    arg.js.type = type;
    chan.send(arg);
  }
  
  return chan;		
}

// create a reliable channel with a friendlier interface
function channel(type, arg, callback)
{
  var hn = this;
  if(type.substr(0,1) !== "_") type = "_"+type;
  var chan = {inq:[], outq:[], outSeq:0, inDone:-1, outConfirmed:-1, lastAck:-1, callback:callback};
  chan.id = arg.id || local.randomHEX(16);
	hn.chans[chan.id] = chan;
  chan.timeout = arg.timeout || defaults.chan_timeout;
  // for now all reliable channels are app ones
  chan.type = (type.substr(0,1) == "_") ? type : "_"+type;
  chan.hashname = hn.hashname; // for convenience

  debug("new channel",hn.hashname,chan.type);

  // used by app to change how it interfaces with the channel
  chan.wrap = function(wrap)
  {
    var chan = this;
    if(!exports.channelWraps[wrap]) return false;
    exports.channelWraps[wrap](chan);
    return chan;
  }

  // called to do eventual cleanup
  chan.done = function(){
    if(chan.ended) return; // prevent multiple calls
    chan.ended = true;
    debug("channel done",chan.id);
    setTimeout(function(){
      // fire .callback(err) on any outq yet?
      delete hn.chans[chan.id];
    }, chan.timeout);
  };

  // used to internally fail a channel, timeout or connection failure
  chan.fail = function(packet){
    if(chan.errored) return; // prevent multiple calls
    chan.errored = packet;
    chan.callback(packet.js.err, packet, chan, function(){});
    chan.done();
  }

  // simple convenience wrapper to end the channel
  chan.end = function(){
    chan.send({end:true});
  };

  // errors are hard-send-end
  chan.err = function(err){
    if(chan.errored) return;
    chan.errored = {js:{err:err,c:chan.id}};
    hn.send(chan.errored);
    chan.done();
  };

	// process packets at a raw level, handle all miss/ack tracking and ordering
	chan.receive = function(packet)
	{
    // if it's an incoming error, bail hard/fast
    if(packet.js.err) return chan.fail(packet);

    // in errored state, only/always reply with the error and drop
    if(chan.errored) return chan.send(chan.errored);

	  // process any valid newer incoming ack/miss
	  var ack = parseInt(packet.js.ack);
    if(ack > chan.outSeq) return warn("bad ack, dropping entirely",chan.outSeq,ack);
	  var miss = Array.isArray(packet.js.miss) ? packet.js.miss : [];
	  if(miss.length > 100) {
      warn("too many misses", miss.length, chan.id, packet.from.address);
	    miss = miss.slice(0,100);
	  }
	  if(miss.length > 0 || ack > chan.lastAck)
	  {
      debug("miss processing",ack,chan.lastAck,miss,chan.outq.length);
	    chan.lastAck = ack;
	    // rebuild outq, only keeping newer packets, resending any misses
	    var outq = chan.outq;
	    chan.outq = [];
	    outq.forEach(function(pold){
	      // packet acknowleged!
	      if(pold.js.seq <= ack) {
	        if(pold.callback) pold.callback();
	        return;
	      }
	      chan.outq.push(pold);
	      if(miss.indexOf(pold.js.seq) == -1) return;
	      // resend misses but not too frequently
	      if(Date.now() - pold.resentAt < 1000) return;
	      pold.resentAt = Date.now();
	      chan.ack(pold);
	    });
	  }
    
    // don't process packets w/o a seq, no batteries included
    var seq = packet.js.seq;
    if(!(seq >= 0)) return;

    // auto trigger an ack in case none were sent
    if(!chan.acker) chan.acker = setTimeout(function(){ delete chan.acker; chan.ack();}, defaults.chan_autoack);

	  // drop duplicate packets, always force an ack
	  if(seq <= chan.inDone || chan.inq[seq-(chan.inDone+1)]) return chan.forceAck = true;
  
	  // drop if too far ahead, must ack
	  if(seq-chan.inDone > defaults.chan_inbuf)
    {
      warn("chan too far behind, dropping", seq, chan.inDone, chan.id, packet.from.address);
      return chan.forceAck = true;
    }

	  // stash this seq and process any in sequence, adjust for yacht-based array indicies
	  chan.inq[seq-(chan.inDone+1)] = packet;
    debug("INQ",Object.keys(chan.inq),chan.inDone,chan.handling);
    chan.handler();
	}
  
  // wrapper to deliver packets in series
  chan.handler = function()
  {
    if(chan.handling) return;
    var packet = chan.inq[0];
    // always force an ack when there's misses yet
    if(!packet && chan.inq.length > 0) chan.forceAck = true;
    if(!packet) return;
    chan.handling = true;
    var err = packet.js.err||packet.js.end;
    packet.js = packet.js._ || {}; // unescape all content json
    chan.callback(err, packet, chan, function(){
      chan.inq.shift();
      chan.inDone++;
      chan.handling = false;
      chan.handler();
    });
  }
  
  // resend the last sent packet if it wasn't acked
  chan.resend = function()
  {
    if(chan.ended) return;
    if(!chan.outq.length) return;
    var lastpacket = chan.outq[chan.outq.length-1];
    // timeout force-end the channel
    if(Date.now() - lastpacket.sentAt > chan.timeout) return chan.fail({js:{err:"timeout"}});
    debug("channel resending");
    chan.ack(lastpacket);
    setTimeout(chan.resend, defaults.chan_resend); // recurse until chan_timeout
  }

  // add/create ack/miss values and send
	chan.ack = function(packet)
	{
    if(!packet) debug("ACK CHECK",chan.id,chan.outConfirmed,chan.inDone);

	  // these are just empty "ack" requests
	  if(!packet)
    {
      // drop if no reason to ack so calling .ack() harmless when already ack'd
      if(!chan.forceAck && chan.outConfirmed == chan.inDone) return;
      packet = {js:{}};
    }
    chan.forceAck = false;
    
    // confirm only what's been processed
	  if(chan.inDone >= 0) chan.outConfirmed = packet.js.ack = chan.inDone;

	  // calculate misses, if any
    delete packet.js.miss; // when resending packets, make sure no old info slips through
	  if(chan.inq.length > 0)
	  {
	    packet.js.miss = [];
	    for(var i = 0; i < chan.inq.length; i++)
	    {
	      if(!chan.inq[i]) packet.js.miss.push(chan.inDone+i+1);
	    }
	  }
    
    // now validate and send the packet
    packet.js.c = chan.id;
    debug("SEND",chan.type,JSON.stringify(packet.js));
    hn.send(packet);

    // catch whenever it was ended to start cleanup
    if(packet.js.end) chan.done();
  }

  // send content reliably
	chan.send = function(arg)
	{
    if(chan.ended) return warn("can't send to an ended channel");

    // create a new packet from the arg
    if(!arg) arg = {};
    var packet = {};
    packet.js = {_:arg.js};
    if(arg.type) packet.js.type = arg.type;
    if(arg.end) packet.js.end = arg.end;
    packet.body = arg.body;
    packet.callback = arg.callback;

    // do durable stuff
	  packet.js.seq = chan.outSeq++;

	  // reset/update tracking stats
    packet.sentAt = Date.now();
    chan.outq.push(packet);
    
    // add optional ack/miss and send
    chan.ack(packet);

    // to auto-resend if it isn't acked
    if(chan.resender) clearTimeout(chan.resender);
    chan.resender = setTimeout(chan.resend, defaults.chan_resend);
    return chan;
	}
  
  // send optional initial packet with type set
  if(arg.js)
  {
    arg.type = type;
    chan.send(arg);
  }

  return chan;		
}

// someone's trying to connect to us, send an open to them
function inConnect(err, packet, chan)
{
  var der = local.der2der(packet.body);
  var to = packet.from.self.whois(local.der2hn(der));
  if(!to || !packet.js.ip || typeof packet.js.port != 'number') return warn("invalid connect request from",packet.from.address,packet.js);
  // if no ipp yet, save them
  if(!to.ip) {
    to.ip = packet.js.ip;
    to.port = parseInt(packet.js.port);
  }
  // if possible NAT-local given, cache that for the open flow too
  if(packet.from.self.nat && packet.js.local && typeof packet.js.local.ip == "string" && typeof packet.js.local.port == "number" && packet.js.local.ip != to.ip) to.local = packet.js.local;
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
function inPeer(err, packet, chan)
{
  if(!isHEX(packet.js.peer, 64)) return warn("invalid peer of", packet.js.peer, "from", packet.from.address);

  var peer = packet.from.self.whois(packet.js.peer);
  if(!peer.lineIn) return; // these happen often as lines come/go, ignore dead peer requests
  // send a single lossy packet
  var js = {type:"connect", end:true, ip:packet.from.ip, port:packet.from.port, c:local.randomHEX(16)};
  if(packet.js.local && packet.js.local.ip != packet.from.ip) js.local = packet.js.local; // relay any optional local information
  peer.send({js:js, body:packet.from.der});
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
function inSeek(err, packet, chan)
{
  if(err) return;
  if(!isHEX(packet.js.seek, 64)) return warn("invalid seek of ", packet.js.seek, "from:", packet.from.address);

  // now see if we have anyone to recommend
  var answer = {end:true, see:packet.from.self.nearby(packet.js.seek).map(function(hn){ return hn.address; })};
  chan.send({js:answer});
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