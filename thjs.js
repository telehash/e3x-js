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
defaults.mesh_timer = 25*1000; // how often the DHT mesh maintenance runs, twice a minute, must be <1min to maintain NAT mappings
defaults.idle_timeout = 60*1000; // destroy lines that are idle too long
defaults.mesh_max = 250; // maximum number of nodes to maintain (minimum one packet per mesh timer)

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
  var self = {seeds:[], locals:[], lines:{}, all:{}, buckets:[], capacity:[], rels:{}, raws:{}};
  self.private = local.pri2key(key.private);
  self.public = local.pub2key(key.public);
  self.der = local.key2der(self.public);
  self.address = self.hashname = local.der2hn(self.der);
  self.nat = true;
  if(args.family) self.family = args.family;
  if(args.ip) self.ip = args.ip;
  if(args.port) self.port = args.port;

  // udp socket stuff
  self.pcounter = 1;
  self.receive = receive;
  // outgoing packets to the network
	self.send = function(to, msg){
    if(!to) return warn("send called w/ no network, dropping");
    to.lastOut = Date.now();
    // a relay network must be resolved to the channel and wrapped/sent that way
    if(to.type == "relay")
    {
      var via = self.whois(to.via);
      if(!via || !via.chans[to.id]) return debug("dropping dead relay via",to.via);
      return via.chans[to.id].send({body:msg});
    }
    // hand rest to the external sending function passed in
    debug("out",(typeof msg.length == "function")?msg.length():msg.length,JSON.stringify(to));
	  send(to, msg);
	};
  self.setIP = function(ip)
  {
    var updated = false;
    if(self.ip && self.ip != ip) updated = true;
    self.ip = ip;
    if(updated) meshPing(self);
  }
  
  // need some seeds to connect to, addSeed({ip:"1.2.3.4", port:5678, public:"PEM"})
  self.addSeed = addSeed;
	
	// map a hashname to an object, whois(hashname)
	self.whois = whois;
  
  // connect to the network, online(callback(err))
  self.online = online;

  // handle new reliable channels coming in from anyone
  self.listen = function(type, callback){
    if(typeof type != "string" || typeof callback != "function") return warn("invalid arguments to listen");
    if(type.substr(0,1) !== "_") type = "_"+type;
    self.rels[type] = callback;
  };
  // advanced usage only
  self.raw = function(type, callback){
    if(typeof type != "string" || typeof callback != "function") return warn("invalid arguments to raw");
    self.raws[type] = callback;
  };
  
	// internal listening unreliable channels
	self.raws["peer"] = inPeer;
	self.raws["connect"] = inConnect;
	self.raws["seek"] = inSeek;
	self.raws["relay"] = inRelay;
	self.raws["path"] = inPath;

  // primarily internal, to seek/connect to a hashname
  self.seek = seek;
  self.via = myVia;
  
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

// every 25 seconds do the maintenance work for peers
function meshLoop(self)
{
  debug("MESHA")
//  meshReap(self); // remove any dead ones, temporarily disabled due to node crypto compiled cleanup bug
  meshElect(self); // which ones go into buckets
  meshPing(self); // ping all of them
  debug("MESHZ")
  setTimeout(function(){meshLoop(self)}, defaults.mesh_timer);
}

// delete any defunct hashnames!
function meshReap(self)
{
  var hn;
  function del(why)
  {
    if(hn.lineOut) delete self.lines[hn.lineOut];
    delete self.all[hn.hashname];
    debug("reaping ", hn.hashname, why);
  }
  Object.keys(self.all).forEach(function(h){
    hn = self.all[h];
    debug("reap check",hn.hashname,Date.now()-hn.sentAt,Date.now()-hn.recvAt,Object.keys(hn.chans).length);
    if(hn.isSeed) return;
    if(Object.keys(hn.chans).length > 0) return; // let channels clean themselves up
    if(Date.now() - hn.at < defaults.idle_timeout) return; // always leave n00bs around for a while
    if(!hn.sentAt) return del("never sent anything, gc");
    if(!hn.recvAt) return del("sent open, never received");
    if(Date.now() - hn.sentAt > defaults.idle_timeout) return del("we stopped sending to them");
    if(Date.now() - hn.recvAt > defaults.idle_timeout) return del("they stopped responding to us");
  });
}

// drop hn into it's appropriate bucket
function bucketize(self, hn)
{
  if(!hn.bucket) hn.bucket = dhash(self.hashname, hn.hashname);
  if(!self.buckets[hn.bucket]) self.buckets[hn.bucket] = [];
  if(self.buckets[hn.bucket].indexOf(hn) == -1) self.buckets[hn.bucket].push(hn);
}

// update which lines are elected to keep, rebuild self.buckets array
function meshElect(self)
{
  // sort all lines into their bucket, rebuild buckets from scratch (some may be GC'd)
  self.buckets = []; // sparse array, one for each distance 0...255
  self.capacity = [];
  Object.keys(self.lines).forEach(function(line){
    bucketize(self, self.lines[line]);
  });
  debug("BUCKETS",Object.keys(self.buckets));
  var spread = parseInt(defaults.mesh_max / Object.keys(self.buckets).length);
  if(!(spread > 1)) spread = 1;

  // each bucket only gets so many lines elected
  Object.keys(self.buckets).forEach(function(bucket){
    var elected = 0;
    self.buckets[bucket].forEach(function(hn){
      if(!hn.alive) return;
      // TODO can use other health quality metrics to elect better/smarter ones
      hn.elected = (elected++ <= spread) ? true : false;
    });
    self.capacity[bucket] = spread - elected; // track any capacity left per bucket
  });
}

// every line that needs to be maintained, ping them
function meshPing(self)
{
  Object.keys(self.lines).forEach(function(line){
    var hn = self.lines[line];
    // have to be elected or a line with a channel open (app)
    if(!(hn.elected || Object.keys(hn.chans).length > 0)) return;
    // approx no more than once a minute
    if(((Date.now() - hn.sentAt) + defaults.mesh_timer) < defaults.idle_timeout) return;
    // seek ourself to discover any new hashnames closer to us for the buckets, used recursively
    function ping(to)
    {
      debug("mesh ping",to.bucket,to.hashname);
      to.raw("seek", {js:{"seek":self.hashname}, timeout:3000}, function(err, packet){
        if(!Array.isArray(packet.js.see)) return;
        // load any sees to look for potential bucket candidates
        packet.js.see.forEach(function(address){
          var sug = self.whois(address);
          if(!sug) return;
          sug.via(to, address);
          if(sug === self || sug.bucket) return; // already bucketized
          // if their bucket has capacity, ping them
          sug.bucket = dhash(self.hashname, hn.hashname);
          if(self.capacity[sug.bucket] === undefined) self.capacity[sug.bucket] = 3; // safe default for a new bucket
          if(self.capacity[sug.bucket]-- >= 0) ping(sug);
        });
      });
    }
    ping(hn);
  });
}

function addSeed(arg) {
  var self = this;
  if(!arg.pubkey) return warn("invalid args to addSeed");
  var der = local.key2der(arg.pubkey);
  var seed = self.whois(local.der2hn(der));
  if(!seed) return warn("invalid seed info",arg);
  if(seed === self) return; // can't add ourselves as a seed
  seed.der = der;
  if(arg.ip)
  {
    var id = arg.ip+":"+arg.port;
    if(!seed.paths[id]) seed.paths[id] = {id:id, type:"ipv4", ip:arg.ip, port:arg.port, priority:0};    
    seed.address = [seed.hashname,arg.ip,arg.port].join(","); // given ip:port should always be the most valid
  }
  if(arg.http)
  {
    if(!seed.paths[arg.http]) seed.paths[arg.http] = {id:arg.http, type:"http",priority:-1};
  }
  seed.isSeed = true;
  self.seeds.push(seed);
}

// when we get a via to ourselves, check address information
function myVia(from, address)
{
  if(typeof address != "string") return warn("invalid see address",address);
  var self = this;
  var parts = address.split(",");
  if(parts.length != 3 || parts[1].split(".").length != 4 || !(parseInt(parts[2]) > 0)) return;
  if(parts[0] !== self.hashname) return;
  // if it's a seed (trusted) update our known public IP/Port
  if(from.isSeed || !self.pubip || self.pubip == "127.0.0.1")
  {
    self.pubip = parts[1];
    self.pubport = parseInt(parts[2]);
    self.address = [self.hashname,self.pubip,self.pubport].join(",");
  }else{
    // TODO multiple public IPs?
  }
  // detect when not NAT'd
  self.nat = (self.ip == self.pubip && self.port == self.pubport) ? false : true;  
  debug("NAT",self.nat,self.address,self.ip,self.port);
}

function online(callback)
{
	var self = this;
  // ping lan
  self.lanToken = local.randomHEX(16);
  self.send({type:"ipv4", lan:true, ip:"255.255.255.255", port:42424}, local.pencode({type:"lan",lan:self.lanToken}));
  // safely callback only once or when all seeds failed
  function done(err)
  {
    if(!dones) return; // already called back
    // success!
    if(!err)
    {
      callback();
      dones = 0;
      meshLoop(self);
      return;
    }
    dones--;
    // failed
    if(!dones) callback(err);
  }
  var dones = self.seeds.length;
  if(!dones) {
    warn("no seeds");
    dones++;
    return done();
  }
	self.seeds.forEach(function(seed){
    seed.seek(self.hashname, function(err, see){
      if(Array.isArray(see)) see.forEach(function(item){
        self.via(seed, item); // myVia()
      });
      done(err);
    })
	})
}

// self.receive, raw incoming udp data
function receive(msg, path)
{
	var self = this;
  var packet = local.pdecode(msg);
  if(!packet) return warn("failed to decode a packet from", path, msg.toString());
  if(Object.keys(packet.js).length == 0) return; // empty packets are NAT pings
  
  packet.sender = path;
  packet.id = self.pcounter++;
  packet.at = Date.now();
  debug("in",(typeof msg.length == "function")?msg.length():msg.length,path.ip,path.port, packet.js.type, packet.body && packet.body.length);

  // handle any LAN notifications
  if(path.lan) return inLan(self, packet);
  if(packet.js.type == "lan") return inLanSeed(self, packet);

  if(typeof packet.js.iv != "string" || packet.js.iv.length != 32) return warn("missing initialization vector (iv)", path);

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
    if (typeof open.js.at != "number") return warn("invalid at", open.js.at);
    if (from.openAt && open.js.at <= from.openAt) return; // skip dups

    // update values
    var line = {};
    debug("inOpen verified", from.hashname);
    from.openAt = open.js.at;
    from.der = open.rsa;
    from.recvAt = Date.now();
    from.lineIn = open.js.line;

    // this will send an open if needed
    from.open(path);

    // line is open now!
    local.openline(from, open);
    debug("line open",from.hashname,from.lineOut,from.lineIn);
    self.lines[from.lineOut] = from;
    bucketize(self, from); // add to their bucket
    
    // add this path in
    from.pathIn(path);

    // resend the last sent packet again
    if (from.lastPacket) {
      var packet = from.lastPacket;
      delete from.lastPacket;
      from.send(packet)
    }
    
    // if it was a lan seed, add them
    if(from.local && self.locals.indexOf(from) == -1) self.locals.push(from);

    return;
	}

  // or it's a line
  if(packet.js.type == "line")
	{
	  var line = packet.from = self.lines[packet.js.line];

	  // a matching line is required to decode the packet
	  if(!line) return debug("unknown line received", packet.js.line, JSON.stringify(packet.sender));

		// decrypt and process
	  local.delineize(packet);
		if(!packet.lineok) return debug("couldn't decrypt line",packet.sender);
    line.receive(packet);
    return;
	}
  
  if(Object.keys(packet.js).length > 0) warn("dropping incoming packet of unknown type", packet.js, packet.sender);
}

// this creates a hashname identity object (or returns existing)
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
  
  // make a new one
  hn = self.all[hashname] = {hashname:hashname, chans:{}, self:self, paths:{}, isAlive:0};
  hn.address = hashname;
  hn.at = Date.now();

  // to create a new channels to this hashname
  hn.start = channel;
  hn.raw = raw;

  // manage network information consistently, called on all validated incoming packets
  hn.pathIn = function(path, isOpen)
  {
    // anything incoming means hn is alive
    hn.alive = true;

    // always normalize to ipv4 address as default
    if(!path.id)
    {
      path.type = "ipv4";
      path.id = path.ip+":"+path.port;
    }

    // just use existing path entry
    if(hn.paths[path.id])
    {
      path = hn.paths[path.id];
    }else{
      // store a new path
      hn.paths[path.id] = path;
      // when either multiple networks or only relay, trigger a sync (slightly delayed so other stuff can happen first)
      if(Object.keys(hn.paths).length > 1 || path.type == "relay") setTimeout(hn.sync,1000);
      // update address
      if(path.type == "ipv4") hn.address = [hn.hashname,path.ip,path.port].join(",");
    }
    
    // track last timestamp
    path.lastIn = Date.now();
    
    // always update to minimum 0 here
    if(typeof path.priority != "number" || path.priority < 0) path.priority = 0;

    return path;
  }
  
  // try to send a packet to a hashname, doing whatever is possible/necessary
  hn.send = function(packet){
    // if there's a line, try sending it via a valid network path!
    if(hn.lineIn)
    {
      debug("line sending",hn.hashname,hn.lineIn);
      var lined = local.lineize(hn, packet);
      
      // directed packets are a special case (path testing), dump and forget
      if(packet.direct) return self.send(packet.direct, lined);
      
      hn.sentAt = Date.now();

      // validate if a network path is acceptable to stop at
      function validate(path)
      {
        if(!path.lastIn || !path.lastOut) return false; // haven't received/sent (shouldn't be possible)
        if(path.lastIn > path.lastOut) return true; // received any newer than sent, good
        if((path.lastOut - path.lastIn) < 5000) return true; // received within 5sec of last sent
        return false; // there are cases where it's still valid, but it's always safer to assume otherwise
      }

      // sort all possible paths by preference, priority and recency
      var paths = Object.keys(hn.paths).sort(function(a,b){
        if(packet.to && a === packet.to) return 1; // always put the .to at the top of the list, if any
        a = hn.paths[a]; b = hn.paths[b];
        if(a.priority == b.priority) return b.lastIn - a.lastIn;
        return b.priority - a.priority;
      });
    
      // try them in order until there's a valid one
      for(var i = 0; i < paths.length; i++)
      {
        // validate first since it uses .lastOut which .send updates
        var valid = validate(hn.paths[paths[i]]);
        self.send(hn.paths[paths[i]], lined);
        if(valid) return; // any valid path means we're done!
      }
    }

    // we've fallen through, either no line, or no valid paths
    hn.alive = false;
    hn.lastPacket = packet; // will be resent if/when an open is received
    hn.open(); // always try an open again

    // also try using any via informtion to create a new line
    function vias()
    {
      if(!hn.vias) return;
      hn.sentOpen = false; // whenever we send a peer, we'll always need to resend any open regardless
      // try to connect vias
      var todo = hn.vias;
      delete hn.vias; // never use more than once
      Object.keys(todo).forEach(function(via){
        var address = todo[via].split(",");
        if(address.length == 3 && address[1].split(".").length == 4 && parseInt(address[2]) > 0)
        {
          // NAT hole punching
          var to = {type:"ipv4",ip:address[1],port:parseInt(address[2])};
          self.send(to,local.pencode());
          // if possibly behind the same NAT, set flag to allow/ask for a relay
          if(self.nat && address[1] == self.pubip) hn.relay = true;
        }else{ // no ip address, must relay
          hn.relay = true;
        }
        self.whois(via).peer(hn.hashname, hn.relay); // send the peer request
      });
    }
    
    // if there's via information, just try that
    if(hn.vias) return vias();
    

    // never too fast, worst case is to try to seek again
    if(!hn.sendSeek || (Date.now() - hn.sendSeek) > 5000)
    {
      hn.sendSeek = Date.now();
      self.seek(hn, function(err){
        if(!hn.lastPacket) return; // packet was already sent elsewise
        vias(); // process any new vias
      });      
    }

  }

  // handle all incoming line packets
  hn.receive = function(packet)
  {
//    if((Math.floor(Math.random()*10) == 4)) return warn("testing dropping randomly!");
    if(!packet.js || !isHEX(packet.js.c, 32)) return warn("dropping invalid channel packet");

    debug("LINEIN",JSON.stringify(packet.js));
    hn.recvAt = Date.now();
    // normalize/track sender network path
    packet.sender = hn.pathIn(packet.sender);

    // find any existing channel
    var chan = hn.chans[packet.js.c];
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
        hn.send({js:{err:err,c:packet.js.c}});
      }
      return;
    }
    // make the correct kind of channel;
    var kind = (listening == self.raws) ? "raw" : "start";
    var chan = hn[kind](packet.js.type, {id:packet.js.c}, listening[packet.js.type]);
    chan.receive(packet);
  }
  
  // track who told us about this hn
  hn.via = function(from, address)
  {
    if(typeof address != "string") return warn("invalid see address",address);
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
        tries = 4; // prevent multiple callbacks
        callback(packet.js.err,Array.isArray(packet.js.see)?packet.js.see:[]);
      });
    }
    seek();
  }
  
  // send a simple lossy peer request, don't care about answer
  hn.peer = function(hashname, relay)
  {
    var js = {type:"peer", end:true, "peer":hashname, c:local.randomHEX(16)};
    if(relay) js.relay = true;
    hn.send({js:js});
  }

  // force send an open packet, direct overrides the network
  hn.open = function(direct)
  {
    if(!hn.der) return; // can't open if no key
    if(!direct && Object.keys(hn.paths).length == 0) return debug("can't open, no path");
    // don't send again if we've sent one in the last few sec, prevents connect abuse
    if(hn.sentOpen && (Date.now() - hn.sentOpen) < 2000) return;
    hn.sentOpen = Date.now();

    // generate just one open packet, so recipient can dedup easily if they get multiple
    var open = local.openize(self, hn);

    // send directly if instructed
    if(direct){
      if(direct.type == "relay")
      {
        var relay = self.whois(direct.via);
        relay.raw("relay", {js:{"to":hn.hashname},body:open}, inRelayMe);
      }else{
        self.send(direct, open);        
      }
    }else{
      // always send to all known paths, increase resiliency
      Object.keys(hn.paths).forEach(function(id){
        self.send(hn.paths[id], open);
      });      
    }

  }
  
  // send a full network path sync, callback(true||false) if err (no networks)
  hn.sync = function(callback)
  {
    if(!callback) callback = function(){};
    debug("syncing",hn.hashname,Object.keys(hn.paths).join(","));
    var refcnt = Object.keys(hn.paths).length;

    // empty. fail the line and reset the hn
    if(refcnt == 0) return callback();

    // check all paths at once
    Object.keys(hn.paths).forEach(function(id){
      var path = hn.paths[id];
      var js = {};
      // our outgoing priority of this path
      js.priority = (path.type == "ipv4") ? 1 : 0;
      // include local ip/port if we're relaying to them
      if(hn.relay && path.type == "relay") js.alts = [{type:"ipv4", ip:self.ip, port:self.port}];
      hn.raw("path",{js:js, timeout:3000, direct:path}, function(err, packet){
        // when it actually errored, lower priority
        if(err && err !== true) path.priority = -1;
        else inPath(true, packet); // handles any response .priority and .alts
        // processed all paths, done
        if((--refcnt) == 0) callback();
      });
    });
  }

  return hn;
}

// seek the dht for this hashname
function seek(hn, callback)
{
  var self = this;
  if(typeof hn == "string") hn = self.whois(hn);
  if(hn === self) return callback("can't seek yourself");
  if(hn.seeking) return callback("already seeking");
  hn.seeking = true;

  var isDone = false;
  function done(err)
  {
    if(isDone) return;
    isDone = true;
    hn.seeking = false;
    callback(err);
  }

  var did = {};
  var doing = {};
  var queue = [];
  var closest = 255;
  self.nearby(hn.hashname).forEach(function(near){
    if(near === hn) return; // ignore the one we're seeking
    if(queue.indexOf(near.hashname) == -1) queue.push(near.hashname);
  });
  // always process potentials in order
  function sort()
  {
    queue = queue.sort(function(a,b){
      return dhash(hn.hashname,a) - dhash(hn.hashname,b)
    });
  }
  sort();

  // main loop, multiples of these running at the same time
  function loop(onetime){
    if(isDone) return;
    debug("SEEK LOOP",queue);
    // if nothing left to do and nobody's doing anything, failed :(
    if(Object.keys(doing).length == 0 && queue.length == 0) return done("failed to find the hashname");
    
    // get the next one to ask
    var mine = onetime||queue.shift();
    if(!mine) return; // another loop() is still running

    // if we found it, yay! :)
    if(mine == hn.hashname) return done();
    // skip dups
    if(did[mine] || doing[mine]) return onetime||loop();
    var distance = dhash(hn.hashname, mine);
    if(distance > closest) return onetime||loop(); // don't "back up" further away
    if(!self.seeds[mine]) closest = distance; // update distance if not talking to a seed
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
      onetime||loop();
    });
  }
  
  // start three of them
  loop();loop();loop();
  
  // also force query any locals
  self.locals.forEach(function(local){loop(local.hashname)});
}

// create an unreliable channel
function raw(type, arg, callback)
{
  var hn = this;
  var chan = {type:type, callback:callback};
  chan.id = arg.id || local.randomHEX(16);
	hn.chans[chan.id] = chan;
  
  // raw channels always timeout/expire after the last sent/received packet
  chan.timeout = arg.timeout||defaults.chan_timeout;
  function timer()
  {
    if(chan.timer) clearTimeout(chan.timer);
    chan.timer = setTimeout(function(){
      if(!hn.chans[chan.id]) return; // already gone
      delete hn.chans[chan.id];
      chan.callback("timeout",{js:{err:"timeout"}},chan);
    }, chan.timeout);
  }

  chan.hashname = hn.hashname; // for convenience

  debug("new unreliable channel",hn.hashname,chan.type);

	// process packets at a raw level, very little to do
	chan.receive = function(packet)
	{
    // if err'd or ended, delete ourselves
    if(packet.js.err || packet.js.end) delete hn.chans[chan.id];
    chan.last = packet.sender; // cache last received network
    chan.callback(packet.js.err||packet.js.end, packet, chan);
    timer();
  }

  // minimal wrapper to send raw packets
  chan.send = function(packet)
  {
    if(!packet.js) packet.js = {};
    packet.js.c = chan.id;
    debug("SEND",chan.type,JSON.stringify(packet.js));
    if(!packet.to && chan.last) packet.to = chan.last; // always send back to the last received for this channel
    hn.send(packet);
    // if err'd or ended, delete ourselves
    if(packet.js.err || packet.js.end) delete hn.chans[chan.id];
    timer();
  }
  
  // dummy stub
  chan.fail = function(){}

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
    if(Date.now() - lastpacket.sentAt > chan.timeout)
    {
      chan.fail({js:{err:"timeout"}});
      return;
    }
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
  if(!packet.body) return;
  var der = local.der2der(packet.body);
  var to = packet.from.self.whois(local.der2hn(der));
  if(!to) return warn("invalid connect request from",packet.from.address,packet.js);
  to.der = der;

  // try the suggested ip info
  if(typeof packet.js.ip == "string" && typeof packet.js.port == "number")
  {
    var path = {ip:packet.js.ip,port:packet.js.port};
    path.type = (path.ip.indexOf(":") > 0) ? "ipv6" : "ipv4";
    to.open(path);
  }
  
  // TODO try any .alts

  // if relay is requested, try that
  if(packet.js.relay === true) to.open({type:"relay",via:packet.from.hashname});
}

// be the middleman to help NAT hole punch
function inPeer(err, packet, chan)
{
  if(!isHEX(packet.js.peer, 64)) return;

  var peer = packet.from.self.whois(packet.js.peer);
  if(!peer.lineIn) return; // these happen often as lines come/go, ignore dead peer requests
  // send a single lossy packet
  var js = {type:"connect", end:true, c:local.randomHEX(16)};
  // set any IP values based on the sender
  if(packet.sender.type == "ipv4" || packet.sender.type == "ipv6"){
    js.ip = packet.sender.ip;
    js.port = packet.sender.port;
  }else{
    js.relay = true; // if no ip information, we must relay    
  }
  // TODO copy .alts
  if(packet.js.relay === true) js.relay = true; // pass through relay flag
  peer.send({js:js, body:packet.from.der});
}

// packets coming in to me
function inRelayMe(err, packet, chan)
{
  if(err) return; // TODO clean up nets?
  if(!packet.body) return warn("relay in w/ no body",packet.js,packet.from.address);
  var self = packet.from.self;
  // create a network that maps back to this channel
  var path = {type:"relay",id:chan.id,via:packet.from.hashname};
  self.receive(packet.body, path);
}

// proxy packets for two hosts
function inRelay(err, packet, chan)
{
  if(err) return;
  var self = packet.from.self;
  
  // see if this channel is set up to relay already
  if(!chan.pair)
  {
    // new relay channel, validate destination
    if(!isHEX(packet.js.to, 64)) return warn("invalid relay of", packet.js.to, "from", packet.from.address);

    // if it's to us, handle that directly
    if(packet.js.to == self.hashname)
    {
      chan.callback = inRelayMe;
      inRelayMe(err, packet, chan);
      return;
    }

    // if to someone else, save them for future packets
    var to = self.whois(packet.js.to);
    if(!to || !to.lineIn) return warn("relay to unknown line", packet.js.to, packet.from.address);
    
    // set up the reverse channel and x-link them
    chan.pair = to.raw("relay",{id:chan.id},inRelay);
    chan.pair.pair = chan;
  }

  // throttle
  if(!chan.relayed || Date.now() - chan.relayed > 1000)
  {
    chan.relayed = Date.now();
    chan.relays = 0;
  }
  if(chan.relays > 5) return debug("relay too fast, dropping",chan.relays);
  chan.relays++;

  // dumb relay
  chan.relayed = Date.now();
  chan.pair.send(packet);
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
      if(!hn.alive) return; // only see ones we have a line with
      ret[hn.hashname] = hn;
    });
    bucket++;
  }

  // use any if still not full
  if(Object.keys(ret).length < 5) Object.keys(self.lines).forEach(function(line){
    if(Object.keys(ret).length >= 5) return;
    if(!self.lines[line].alive) return;
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
  var answer = {end:true, see:packet.from.self.nearby(packet.js.seek).filter(function(hn){return hn.address;}).map(function(hn){ return hn.address; }).slice(0,5)};
  chan.send({js:answer});
}

// update/respond to network state
function inPath(err, packet, chan)
{
  // check/try any alternate paths
  if(Array.isArray(packet.js.alts)) packet.js.alts.forEach(function(path){
    if(path.type != "ipv4") return; // only supported for now
    path.id = path.ip + ":" + path.port;
    if(packet.from.paths[path.id]) return;
    // a new one, experimentally send it a path
    packet.from.raw("path",{js:{priority:1},direct:path}, inPath);
  });
  // update any optional priority information
  if(typeof packet.js.priority == "number") packet.from.priority = packet.js.priority;
  if(err) return; // bye bye bye!
  
  // need to respond, prioritize everything above relay
  var priority = (packet.sender.type == "relay") ? 0 : 1;
  chan.send({js:{end:true, priority:priority}});
}

// packets coming in from the LAN broadcast receiver
function inLan(self, packet)
{
  if(packet.js.lan == self.lanToken) return; // ignore ourselves
  self.send(packet.sender, local.pencode(packet.js, self.der));
}

// answers from any LAN broadcast notice we sent
function inLanSeed(self, packet)
{
  if(packet.js.lan != self.lanToken) return debug("invalid lan token received")
  if(self.locals.length >= 5) return warn("locals full");
  if(!packet.body) return;
  var der = local.der2der(packet.body);
  var to = self.whois(local.der2hn(der));
  if(!to || to === self) return warn("invalid lan request from",packet.sender);
  to.der = der;
  to.local = true;
  to.open(packet.sender);
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