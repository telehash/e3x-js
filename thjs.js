(function(exports){ // browser||node safe wrapper

var warn = function(){console.log.apply(console,arguments); return undefined; };
var debug = function(){};
//var debug = function(){console.log.apply(console,arguments)};
exports.debug = function(cb){ debug = cb; };
var info = function(){};
//var debug = function(){console.log.apply(console,arguments)};
exports.info = function(cb){ info = cb; };


var defaults = exports.defaults = {};
defaults.chan_timeout = 10000; // how long before for ending durable channels w/ no acks
defaults.seek_timeout = 3000; // shorter tolerance for seeks, is far more lossy
defaults.chan_autoack = 1000; // is how often we auto ack if the app isn't generating responses in a durable channel
defaults.chan_resend = 2000; // resend the last packet after this long if it wasn't acked in a durable channel
defaults.chan_outbuf = 100; // max size of outgoing buffer before applying backpressure
defaults.chan_inbuf = 50; // how many incoming packets to cache during processing/misses
defaults.nat_timeout = 120*1000; // nat timeout for inactivity
defaults.idle_timeout = 5*60*1000; // overall inactivity timeout
defaults.link_timer = 55*1000; // how often the DHT link maintenance runs
defaults.link_max = 256; // maximum number of links to maintain overall (minimum one packet per link timer)
defaults.link_k = 8; // maximum number of links to maintain per bucket

// dependency functions
var local;
exports.localize = function(locals){ local = locals; }

exports.isHashname = function(hex)
{
  return isHEX(hex, 64);
}

// start a hashname listening and ready to go
exports.hashname = function(keys, send)
{
  if(!local) return warn("thjs.localize() needs to be called first");
  if(!keys) return warn("bad args to hashname, requires keys");
  var self = {seeds:[], locals:[], lines:{}, bridges:{}, all:{}, buckets:[], capacity:[], rels:{}, raws:{}, paths:{}, bridgeIVs:{}, TSockets:{}};

  if(keys.parts)
  {
    self.parts = keys.parts;
    var err = local.loadkeys(self,keys);
    if(err) return warn("failed to load keys",err);
    self.address = self.hashname = local.parts2hn(self.parts);
  }else{ // legacy
    if(!keys.public || !keys.private) return warn("bad args to hashname, requires key.public and key.private");
    if(!local.pub2key(keys.public) || !local.pri2key(keys.private)) return warn("key.public and key.private must be valid pem strings");    
    self.private = local.pri2key(keys.private);
    self.public = local.pub2key(keys.public);
    self.der = local.key2der(self.public);
    self.address = self.hashname = local.der2hn(self.der);
  }
  if(typeof send !== "function") return warn("second arg needs to be a function to send packets, is", typeof send);

  // configure defaults
  self.nat = false;
  self.seed = true;

  // udp socket stuff
  self.pcounter = 1;
  self.receive = receive;
  // outgoing packets to the network
	self.send = function(path, msg, to){
    if(!path) return warn("send called w/ no network, dropping");
    path.lastOut = Date.now();
    // a relay network must be resolved to the channel and wrapped/sent that way
    if(path.type == "relay")
    {
      var via = self.whois(path.via);
      if(!via || !via.chans[path.id] || !via.alive)
      {
        debug("dropping dead relay via",JSON.stringify(path),via&&via.alive);
        if(to && to.to == path) delete to.to;
        return;
      }
      // must include the sender path here to detect double-relay
      return via.chans[path.id].send({sender:path, js:{type:"relay",to:to.hashname}, body:msg});
    }
    // hand rest to the external sending function passed in
    debug("out",(typeof msg.length == "function")?msg.length():msg.length,[path.type,path.ip,path.port,path.id].join(","),to&&to.hashname);
	  send(path, msg, to);
	};
  self.pathSet = function(path)
  {
    var updated = (self.paths[path.type] && JSON.stringify(self.paths[path.type]) == JSON.stringify(path));
    self.paths[path.type] = path;
    // if ip4 and local ip, set nat mode
    if(path.type == "ipv4") self.nat = isLocalIP(path.ip);
    // trigger pings if our address changed
    if(self.isOnline && !updated)
    {
      debug("local network updated, checking links")
      linkMaint(self);
    }
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

  // TeleSocket handling
  //   - to listen pass path-only uri "/foo/bar", fires callback(socket) on any incoming matching uri
  //   - to connect, pass in full uri "ts://hashname/path" returns socket
  self.socket = function(uri, callback)
  {
    if(typeof uri != "string") return warn("invalid TS uri")&&false;
    // detect connecting socket
    if(uri.indexOf("ts://") == 0)
    {
      var parts = uri.substr(5).split("/");
      var to = self.whois(parts.shift());
      if(!to) return warn("invalid TS hashname")&&false;
      return to.socket(parts.join("/"));
    }
    if(uri.indexOf("/") != 0) return warn("invalid TS listening uri")&&false;
    debug("adding TS listener",uri)
    self.TSockets[uri] = callback;
  }
	self.rels["ts"] = inTS;
  
	// internal listening unreliable channels
	self.raws["peer"] = inPeer;
	self.raws["connect"] = inConnect;
	self.raws["seek"] = inSeek;
	self.raws["relay"] = inRelay;
	self.raws["path"] = inPath;
	self.raws["bridge"] = inBridge;
	self.raws["link"] = inLink;

  // primarily internal, to seek/connect to a hashname
  self.seek = seek;
  self.bridge = bridge;
  
  linkLoop(self);
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
    chan.callback = function(end, packet, chan, cb)
    {
      cb();
      if(packet.body) bulkIn += packet.body;
      if(!chan.onBulk) return;
      if(end) chan.onBulk(end!==true?end:false, bulkIn);
    }
    // handle (optional) outgoing bulk flow
    chan.bulk = function(data, callback)
    {
      // break data into chunks and send out, no backpressure yet
      while(data)
      {
        var chunk = data.substr(0,1000);
        data = data.substr(1000);
        var packet = {body:chunk};
        if(!data) packet.callback = callback; // last packet gets confirmed
        chan.send(packet);
      }
      chan.end();
    }
	},
  "TS":function(chan){
    chan.socket = {data:"", hashname:chan.hashname, id:chan.id};
    chan.callback = function(err, packet, chan, callback){
      // go online
      if(chan.socket.readyState == 0)
      {
        chan.socket.readyState = 1;
        if(chan.socket.onopen) chan.socket.onopen();
      }
      if(packet.body) chan.socket.data += packet.body;
      if(packet.js.done)
      {
        // allow ack-able onmessage handler instead
        if(chan.socket.onmessageack) chan.socket.onmessageack(chan.socket, callback);
        else callback();
        if(chan.socket.onmessage) chan.socket.onmessage(chan.socket);
        chan.socket.data = "";
      }else{
        callback();
      }
      if(err)
      {
        chan.socket.readyState = 2;
        if(err != true && chan.socket.onerror) chan.socket.onerror(err);
        if(chan.socket.onclose) chan.socket.onclose();
      }
    }
    // set up TS object for external use
    chan.socket.readyState = chan.lastIn ? 1 : 0; // if channel was already active, set state 1
    chan.socket.send = function(data, callback){
      if(chan.socket.readyState != 1) return debug("sending fail to TS readyState",chan.socket.readyState)&&false;
      // chunk it
      while(data)
      {
        var chunk = data.substr(0,1000);
        data = data.substr(1000);
        var packet = {js:{},body:chunk};
        // last packet gets confirmed/flag
        if(!data)
        {
          packet.callback = callback;
          packet.js.done = true;
        }
        debug("TS SEND",chunk.length,packet.js.done);
        chan.send(packet);
      }
    }
    chan.socket.close = function(){
      chan.socket.readyState = 2;
      chan.done();
    }    
  }
}

// do the maintenance work for links
function linkLoop(self)
{
  self.bridgeIVs = {}; // reset IV cache for any bridging
//  hnReap(self); // remove any dead ones, temporarily disabled due to node crypto compiled cleanup bug
  linkMaint(self); // ping all of them
  setTimeout(function(){linkLoop(self)}, defaults.link_timer);
}

// delete any defunct hashnames!
function hnReap(self)
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
    if(Date.now() - hn.at < hn.timeout()) return; // always leave n00bs around for a while
    if(!hn.sentAt) return del("never sent anything, gc");
    if(!hn.recvAt) return del("sent open, never received");
    if(Date.now() - hn.sentAt > hn.timeout()) return del("we stopped sending to them");
    if(Date.now() - hn.recvAt > hn.timeout()) return del("they stopped responding to us");
  });
}

// every link that needs to be maintained, ping them
function linkMaint(self)
{
  // process every bucket
  Object.keys(self.buckets).forEach(function(bucket){
    // sort by age and send maintenance to only k links
    var sorted = self.buckets[bucket].sort(function(a,b){ return a.age - b.age });
    debug("link maintenance on bucket",bucket,sorted.length);
    sorted.slice(0,defaults.link_k).forEach(function(hn){
      if(!hn.linked || !hn.alive) return;
      if((Date.now() - hn.linked.sentAt) < Math.ceil(defaults.link_timer/2)) return; // we sent to them recently
      hn.linked.send({js:{seed:self.seed}});
    });
  });
}

// try to create a bridge to them
function bridge(to, callback)
{
  var self = this;
  debug("trying to start a bridge",to.hashname,JSON.stringify(to.possible));
  if(Object.keys(to.possible).length == 0) return callback(); // no possible paths to bridge to

  var found;
  function start(via, path)
  {
    // try to find a better path type we know the bridge supports
    if(!path) via.paths.forEach(function(p){
      if(!path || to.possible[p.type]) path = to.possible[p.type];
    });
    via.raw("bridge", {js:{to:to.lineIn,from:to.lineOut,path:path}}, function(end, packet){
      // TODO we can try another path and/or via?
      if(end !== true) debug("failed to create bridge",end,via.hashname);
      callback((end==true)?packet.sender:false, via);
    });    
  }
  
  // if there's a bridge volunteer for them already
  if(to.possible.bridge && to.possible.bridge.via) return start(self.whois(to.possible.bridge.via), to.possible.bridge);

  // find any bridge supporting seed
  Object.keys(self.seeds).forEach(function(seed){
    if(found) return;
    seed = self.seeds[seed];
    if(!seed.alive || !seed.bridging) return;
    found = true;
    start(seed);
  });

  // worst case, blind attempt to bridge through the relay
  if(!found && to.to && to.to.type == "relay") return start(self.whois(to.to.via));

  if(!found) return callback();
}

function addSeed(arg) {
  var self = this;
  if(arg.parts)
  {
    var csid = partsMatch(self.parts,arg.parts);
    if(!csid) return warn("no matching parts",arg);
    var seed = self.whois(local.parts2hn(arg.parts));
    if(!seed || !arg.keys) return warn("invalid seed info",arg);
    seed.parts = arg.parts;
    var err;
    if(err = local.loadkey(seed, csid, arg.keys[csid])) return warn("failed to load key",arg.keys[csid],err);
    if(Array.isArray(arg.paths)) arg.paths.forEach(function(path){
      if(pathMatch(path, seed.unpaths)) return;
      seed.unpaths.push(path);
    });
    if(arg.bridge) seed.bridging = true;
    seed.isSeed = true;
    self.seeds.push(seed);
    return;
  }
  
  // legacy format
  if(!arg.pubkey) return warn("invalid args to addSeed");
  var der = local.key2der(arg.pubkey);
  var seed = self.whois(local.der2hn(der));
  if(!seed) return warn("invalid seed info",arg);
  seed.der = der;
  if(arg.ip)
  {
    var path = {type:"ipv4", ip:arg.ip, port:arg.port, priority:-2};
    if(!pathMatch(path, seed.unpaths)) seed.unpaths.push(path);
    seed.address = [seed.hashname,arg.ip,arg.port].join(","); // given ip:port should always be the most valid
  }
  if(arg.ip6)
  {
    var path = {type:"ipv6", ip:arg.ip6, port:arg.port6, priority:-1};
    if(!pathMatch(path, seed.unpaths)) seed.unpaths.push(path);
  }
  if(arg.http)
  {
    var path = {type:"http", http:arg.http, priority:-2};
    if(!pathMatch(path, seed.unpaths)) seed.unpaths.push(path);
  }
  if(arg.bridge) seed.bridging = true;
  seed.isSeed = true;
  self.seeds.push(seed);
}

function online(callback)
{
	var self = this;
  self.isOnline = true;
  // ping lan
  self.lanToken = local.randomHEX(16);
  self.send({type:"lan"}, local.pencode({type:"lan",lan:self.lanToken}));

  var dones = self.seeds.length;
  if(!dones) {
    warn("no seeds");
    return callback();
  }

  // safely callback only once or when all seeds return
  function done()
  {
    if(!dones) return; // already called back
    // success!
    if(Date.now() - self.recvAt < 1000)
    {
      callback();
      dones = 0;
      return;
    }
    dones--;
    // failed
    if(!dones) callback("offline");
  }

	self.seeds.forEach(function(seed){
    seed.link(function(){
      if(seed.alive) seed.sync();
      done();
    });
	});
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
  debug("in",(typeof msg.length == "function")?msg.length():msg.length, packet.js.type, packet.body && packet.body.length,[path.type,path.ip,path.port,path.id].join(","));

  // handle any LAN notifications
  if(packet.js.type == "lan") return inLan(self, packet);
  if(packet.js.type == "seed") return inLanSeed(self, packet);

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

    // make sure this open is legit
    if (typeof open.js.at != "number") return warn("invalid at", open.js.at);
    if(from.openAt)
    {
      if(open.js.at <= from.openAt) return; // ignore dups
      from.sentOpen = 0; // make sure we send a new open
    }

    // open is legit!
    debug("inOpen verified", from.hashname);
    from.recvAt = Date.now();

    // add this path in
    path = from.pathIn(path);

    // don't re-process a duplicate open
    if (from.openAt && open.js.at <= from.openAt) return;

    // update values
    var line = {};
    from.openAt = open.js.at;
    from.der = open.rsa;
    from.lineIn = open.js.line;

    // this will send an open if needed
    from.open(path);

    // line is open now!
    local.openline(from, open);
    debug("line open",from.hashname,from.lineOut,from.lineIn);
    self.lines[from.lineOut] = from;
    
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
	  if(!line) {
	    if(!self.bridges[packet.js.line]) return debug("unknown line received", packet.js.line, JSON.stringify(packet.sender));
      debug("BRIDGE",JSON.stringify(self.bridges[packet.js.line]),packet.js.line);
      if(self.bridgeIVs[packet.js.iv]) return; // drop duplicates
      self.bridgeIVs[packet.js.iv] = true;
      // flat out raw retransmit any bridge packets
      return self.send(self.bridges[packet.js.line],msg);
	  }

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

  // never return ourselves
  if(hashname === self.hashname) return false;

  var hn = self.all[hashname];
	if(hn) return hn;
  
  // make a new one
  hn = self.all[hashname] = {hashname:hashname, chans:{}, self:self, paths:[], unpaths:[], possible:{}, isAlive:0};
  hn.address = hashname;
  hn.at = Date.now();
  hn.bucket = dhash(self.hashname, hashname);
  if(!self.buckets[hn.bucket]) self.buckets[hn.bucket] = [];

  // to create a new channels to this hashname
  hn.start = channel;
  hn.raw = raw;

  // different timeout values based on if there's possibly a nat between us
  hn.timeout = function()
  {
    var ip4 = hn.address.split(",")[1];
    // no ipv4 path, no nat
    if(!ip4 || !self.paths.lan4) return defaults.idle_timeout;
    // if one is local and the other is not
    return (isLocalIP(self.paths.lan4.ip) && !isLocalIP(ip4)) ? defaults.nat_timeout : defaults.idle_timeout;
  }

  // manage network information consistently, called on all validated incoming packets
  hn.pathIn = function(path)
  {
    if(["ipv4","ipv6","http","bridge","relay","webrtc"].indexOf(path.type) == -1)
    {
      warn("unknown path type", JSON.stringify(path));
      return path;
    }
    
    // preserve original
    if(!path.json) path.json = JSON.parse(JSON.stringify(path));

    // relays are special cases, used temporarily and don't get added to .paths
    if(path.type == "relay")
    {
      if(hn.to && hn.to.id == path.id) return hn.to; // already exists
      debug("relay incoming",hn.hashname,JSON.stringify(path));
      info(hn.hashname,path.type,JSON.stringify(path.json));
      hn.to = path; // set new default relay
      hn.alive = false; // a new relay is a red flag
      // trigger sync whenever a relay is added (slightly delayed so other internal async stuff can happen first)
      var started = Date.now();
      setTimeout(function(){
        debug("relay only, trying sync",hn.hashname);
        hn.sync(function(){
          // if we found another path, yay
          if(hn.alive) return debug("relay upgraded, now alive",hn.hashname);
          // only relay yet, try to create a bridge
          self.bridge(hn, function(pathin, via){
            debug("BRIDGING",hn.hashname,pathin,via&&via.hashname);
            if(!pathin) return debug("no bridge");
            hn.bridge = via.hashname;
            // experimentally send direct via the bridge path now
            hn.raw("path",{js:{priority:0},to:pathin}, inPath);
          });
        })
      },10);
      return path;
    }
    
    // anything else incoming means hn is alive
    if(!hn.alive) debug("aliving",hn.hashname,JSON.stringify(path));
    hn.alive = true;
    self.recvAt = Date.now();

    var match = pathMatch(path, hn.paths);
    if(!match)
    {
      // store a new path
      debug("adding new path",JSON.stringify(path),JSON.stringify(hn.paths));
      info(hn.hashname,path.type,JSON.stringify(path.json));
      hn.paths.push(path);
      match = path;
      hn.to = match; // always set most recently created to best!

      // if bridging, and this path is from the bridge, flag it for lower priority
      if(hn.bridge && pathMatch(path, self.whois(hn.bridge).paths)) path.priority = -1;

      // always default to minimum 0 here
      if(typeof path.priority != "number") path.priority = 0;

      // when multiple networks detected, trigger a sync (delayed so caller can continue/respond first)
      if(hn.paths.length > 1) setTimeout(hn.sync,1);

      // update public ipv4 address
      if(path.type == "ipv4" && !isLocalIP(path.ip)) hn.address = [hn.hashname,path.ip,path.port].join(",");
      
      // track overall if we trust them as local
      if(path.type.indexOf("ip") == 0 && isLocalIP(path.ip)) hn.isLocal = true;

      // track overall if they are connected via a public IP network
      if(path.type.indexOf("ip") == 0 && !isLocalIP(path.ip)) hn.isPublic = true;
    }
    
    // track last active timestamp
    match.lastIn = Date.now();
    
    // if better, use it
    if(!pathValid(hn.to) || hn.to.type == "relay") hn.to = match;

    return match;
  }
  
  // try to send a packet to a hashname, doing whatever is possible/necessary
  hn.send = function(packet){
    // if there's a line, try sending it via a valid network path!
    if(hn.lineIn)
    {
      debug("line sending",hn.hashname,hn.lineIn);
      var lined = packet.msg || local.lineize(hn, packet);
      hn.sentAt = Date.now();

      // directed packets are preferred, just dump and done
      if(packet.to) return self.send(packet.to, lined, hn);

      // send to the default best path
      if(hn.to) self.send(hn.to, lined, hn);

      // if it was good, we're done, if not fall through
      if(pathValid(hn.to)) return;
    }

    // we've fallen through, either no line, or no valid paths
    debug("alive failthrough",hn.sendSeek,Object.keys(hn.vias||{}));
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
          var path = {type:"ipv4",ip:address[1],port:parseInt(address[2])};
          self.send(path,local.pencode());
          // if possibly behind the same NAT, set flag to allow/ask to relay a local path
          if(self.nat && address[1] == (self.paths.pub4 && self.paths.pub4.ip)) hn.relayAsk = "local";
        }else{ // no ip address, must relay
          hn.relayAsk = true;
        }
        // TODO, if we've tried+failed a peer already w/o a relay, add relay
        self.whois(via).peer(hn.hashname, hn.relayAsk); // send the peer request
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
    var bucket = dhash(hn.hashname, hashname);
    var prefix = hashname.substr(0, Math.ceil((255-bucket)/4)+2);
    hn.raw("seek", {retry:3, js:{"seek":prefix}}, function(err, packet, chan){
      callback(packet.js.err,Array.isArray(packet.js.see)?packet.js.see:[]);
    });
  }

  // request a new link to them
  hn.link = function(callback)
  {
    var js = {seed:self.seed};
    js.see = self.buckets[hn.bucket].map(function(hn){ return hn.address; }).slice(0,5);
    hn.raw("link", {retry:3, js:js}, function(err, packet, chan){
      if(callback) callback(packet.js.err,Array.isArray(packet.js.see)?packet.js.see:[]);
      inLink(err, packet, chan);
    });
  }
  
  // send a simple lossy peer request, don't care about answer
  hn.peer = function(hashname, relay)
  {
    var js = {type:"peer", end:true, "peer":hashname, c:local.randomHEX(16)};
    js.paths = [];
    if(self.paths.pub4) js.paths.push({type:"ipv4", ip:self.paths.pub4.ip, port:self.paths.pub4.port});
    if(self.paths.pub6) js.paths.push({type:"ipv6", ip:self.paths.pub6.ip, port:self.paths.pub6.port});
    if(self.paths.http) js.paths.push({type:"http", http:self.paths.http.http});
    // note: don't include webrtc since it's private and done during a path sync
    if(hn.isLocal)
    {
      if(self.paths.lan4) js.paths.push({type:"ipv4", ip:self.paths.lan4.ip, port:self.paths.lan4.port});
      if(self.paths.lan6) js.paths.push({type:"ipv6", ip:self.paths.lan6.ip, port:self.paths.lan6.port});      
    }
    if(relay || js.paths.length == 0) js.paths.push({type:"relay", id:local.randomHEX(16)});
    hn.send({js:js});
  }

  // force send an open packet, direct overrides the network
  hn.open = function(direct)
  {
    if(!hn.der) return; // can't open if no key
    if(!direct && hn.paths.length == 0 && hn.unpaths.length == 0) return debug("can't open, no paths");
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
        relay.raw("relay", {id:direct.id, js:{"to":hn.hashname},body:open}, inRelayMe);
      }else{
        self.send(direct, open, hn);        
      }
      return;
    }

    // always send to all known paths, increase resiliency
    hn.paths.forEach(function(path){
      self.send(path, open, hn);
    });

    // also send to any un-verified paths
    hn.unpaths.forEach(function(path){
      self.send(path, open, hn);
    });

  }
  
  // send a full network path sync, callback(true||false) if err (no networks)
  hn.sync = function(callback)
  {
    if(!callback) callback = function(){};
    debug("syncing",hn.hashname,JSON.stringify(hn.paths));
    
    // check which types of paths we have to them
    var types = {};
    hn.paths.forEach(function(path){
      types[path.type] = true;
    });

    // clone the paths and add in relay if one
    var paths = hn.paths.slice();
    if(hn.to && hn.to.type == "relay") paths.push(hn.to);

    // empty. TODO should we do something?
    if(paths.length == 0) return callback();

    // compose all of our known paths we can send to them
    var alts = [];
    // if no ip paths and we have some, signal them
    if(!types.ipv4 && self.paths.pub4) alts.push({type:"ipv4", ip:self.paths.pub4.ip, port:self.paths.pub4.port});
    if(!types.ipv6 && self.paths.pub6) alts.push({type:"ipv6", ip:self.paths.pub6.ip, port:self.paths.pub6.port});
    // if we support http path too
    if(!types.http && self.paths.http) alts.push({type:"http",http:self.paths.http.http});
    // if we support webrtc
    if(!types.webrtc && self.paths.webrtc) alts.push({type:"webrtc", id:local.randomHEX(16)});
    // include local ip/port if we're relaying to them
    if(hn.relayAsk == "local")
    {
      if(self.paths.lan4) alts.push({type:"ipv4", ip:self.paths.lan4.ip, port:self.paths.lan4.port});
      if(self.paths.lan6) alts.push({type:"ipv6", ip:self.paths.lan6.ip, port:self.paths.lan6.port});        
    }

    // check all paths at once
    var refcnt = paths.length;
    paths.forEach(function(path){
      debug("PATHLOOP",paths.length,JSON.stringify(path));
      var js = {};
      js.path = path.json;
      // our outgoing priority of this path
      js.priority = (path.type == "relay") ? 0 : 1;
      if(alts.length > 0) js.paths = alts;
      var lastIn = path.lastIn;
      hn.raw("path",{js:js, timeout:3000, to:path}, function(err, packet){
        // when it actually errored and hasn't been active, invalidate it
        if(err && err !== true && path.lastIn == lastIn) path.lastIn = 0;
        else inPath(true, packet); // handles any response .priority and .paths
        // processed all paths, done
        if((--refcnt) == 0) callback();
      });
    });
  }

  // create an outgoing TeleSocket
  hn.socket = function(pathname)
  {
    if(!pathname) pathname = "/";
    // passing id forces internal/unescaped mode
    var chan = hn.start("ts",{id:local.randomHEX(16),js:{path:pathname}});
    chan.wrap("TS");
    return chan.socket;
  }
  
  return hn;
}

// seek the dht for this hashname
function seek(hn, callback)
{
  var self = this;
  if(typeof hn == "string") hn = self.whois(hn);
  if(!hn) return callback("invalid hashname");

  var did = {};
  var doing = {};
  var queue = [];
  var wise = {};
  var closest = 255;
  
  // load all seeds and sort to get the top 3
  var seeds = []
  Object.keys(self.buckets).forEach(function(bucket){
    self.buckets[bucket].forEach(function(link){
      if(link.hashname == hn) return; // ignore the one we're (re)seeking
      if(link.seed) seeds.push(link);
    });
  });
  seeds.sort(function(a,b){ return dhash(hn.hashname,a.hashname) - dhash(hn.hashname,b.hashname) }).slice(0,3).forEach(function(seed){
    wise[seed.hashname] = true;
    queue.push(seed.hashname);
  });
  
  debug("seek starting with",queue);

  // always process potentials in order
  function sort()
  {
    queue = queue.sort(function(a,b){
      return dhash(hn.hashname,a) - dhash(hn.hashname,b)
    });
  }

  // track when we finish
  function done(err)
  {
    // get all the hashnames we used/found and do final sort to return
    Object.keys(did).forEach(function(k){ if(queue.indexOf(k) == -1) queue.push(k); });
    Object.keys(doing).forEach(function(k){ if(queue.indexOf(k) == -1) queue.push(k); });
    sort();
    while(cb = hn.seeking.shift()) cb(err, queue.slice());
  }

  // track callback(s);
  if(!hn.seeking) hn.seeking = [];
  hn.seeking.push(callback);
  if(hn.seeking.length > 1) return;

  // main loop, multiples of these running at the same time
  function loop(onetime){
    if(!hn.seeking.length) return; // already returned
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
    if(wise[mine]) closest = distance; // update distance if trusted
    doing[mine] = true;
    var to = self.whois(mine);
    to.seek(hn.hashname, function(err, see){
      see.forEach(function(item){
        var sug = self.whois(item);
        if(!sug) return;
        // if this is the first entry and from a wise one, give them wisdom too
        if(wise[to.hashname] && see.indexOf(item) == 0) wise[sug.hashname] = true;
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
  if(!arg.timeout) arg.timeout = defaults.chan_timeout;
  function timer()
  {
    if(chan.timer) clearTimeout(chan.timer);
    chan.timer = setTimeout(function(){
      if(!hn.chans[chan.id]) return; // already gone
      delete hn.chans[chan.id];
      chan.callback("timeout",{from:hn,js:{err:"timeout"}},chan);
    }, arg.timeout);
  }
  chan.timeout = function(timeout)
  {
    arg.timeout = timeout;
    timer();
  }

  chan.hashname = hn.hashname; // for convenience

  debug("new unreliable channel",hn.hashname,chan.type,chan.id);

	// process packets at a raw level, very little to do
	chan.receive = function(packet)
	{
    if(!hn.chans[chan.id]) return debug("dropping receive packet to dead channel",chan.id,packet.js)
    // if err'd or ended, delete ourselves
    if(packet.js.err || packet.js.end) delete hn.chans[chan.id];
    chan.last = packet.sender; // cache last received network
    chan.recvAt = Date.now();
    chan.callback(packet.js.err||packet.js.end, packet, chan);
    timer();
  }

  // minimal wrapper to send raw packets
  chan.send = function(packet)
  {
    if(!hn.chans[chan.id]) return debug("dropping send packet to dead channel",chan.id,packet.js);
    if(!packet.js) packet.js = {};
    packet.js.c = chan.id;
    debug("SEND",chan.type,JSON.stringify(packet.js));
    chan.sentAt = Date.now();
    if(!packet.to && pathValid(chan.last)) packet.to = chan.last; // always send back to the last received for this channel
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
    // retry if asked to
    if(arg.retry)
    {
      var at = 1000;
      function retry(){
        if(!hn.chans[chan.id] || chan.recvAt) return; // means we're gone or received a packet
        chan.send(arg);
        if(at < 4000) at *= 2;
        arg.retry--;
        if(arg.retry) setTimeout(retry, at);
      };
      setTimeout(retry, at);
    }
  }
  
  return chan;		
}

// create a reliable channel with a friendlier interface
function channel(type, arg, callback)
{
  var hn = this;
  var chan = {inq:[], outq:[], outSeq:0, inDone:-1, outConfirmed:-1, lastAck:-1, callback:callback};
  chan.id = arg.id || local.randomHEX(16);
	hn.chans[chan.id] = chan;
  chan.timeout = arg.timeout || defaults.chan_timeout;
  // app originating if no id, be friendly w/ the type, don't double-underscore if they did already
  if(!arg.id && type.substr(0,1) !== "_") type = "_"+type;  
  chan.type = type; // save for debug
  if(chan.type.substr(0,1) != "_") chan.safe = true; // means don't _ escape the json
  chan.hashname = hn.hashname; // for convenience

  debug("new channel",hn.hashname,chan.type,chan.id);

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
    packet.from = hn;
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
    if(!packet.js.end) chan.lastIn = Date.now();

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
    if(!chan.safe) packet.js = packet.js._ || {}; // unescape all content json
    chan.callback(packet.js.end, packet, chan, function(){
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
    packet.js = chan.safe ? arg.js : {_:arg.js};
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
  var self = packet.from.self;
  var der = local.der2der(packet.body);
  var to = self.whois(local.der2hn(der));
  if(!to) return warn("invalid connect request from",packet.from.address,packet.js);
  to.der = der;
  var sentOpen = to.sentOpen;

  // try the suggested paths
  if(Array.isArray(packet.js.paths)) packet.js.paths.forEach(function(path){
    if(typeof path.type != "string") return debug("bad path",JSON.stringify(path));
    // store any path as a possible one
    to.possible[path.type] = path;
    // if they are offering to provide assistance, stash the sender
    if(["bridge","relay"].indexOf(path.type) >= 0) path.via = packet.from.hashname;
    // ignore types that you can't send to directly until you have a line
    if(["bridge","webrtc"].indexOf(path.type) >= 0) return;
    to.sentOpen = sentOpen; // restore throttling var since these are all bunched together, could be refactored better as a batch
    to.open(path);
  });
  
  // if we didn't send any, no valid paths, always try a relay
  if(to.sentOpen == sentOpen) to.open({type:"relay",id:local.randomHEX(16),via:packet.from.hashname});
}

// be the middleman to help NAT hole punch
function inPeer(err, packet, chan)
{
  if(!isHEX(packet.js.peer, 64)) return;
  var self = packet.from.self;

  var peer = self.whois(packet.js.peer);
  if(!peer.lineIn) return; // these happen often as lines come/go, ignore dead peer requests
  // send a single lossy packet
  var js = {type:"connect", end:true, c:local.randomHEX(16)};

  // sanity on incoming paths array
  if(!Array.isArray(packet.js.paths)) packet.js.paths = [];
  
  // insert in incoming IP path, TODO refactor how we overload paths, poor form
  if(packet.sender.type.indexOf("ip") == 0)
  {
    var path = JSON.parse(JSON.stringify(packet.sender)); // clone
    delete path.priority;
    delete path.lastIn;
    delete path.lastOut;
    packet.js.paths.push(path);    
  }
  
  // load/cleanse all paths
  js.paths = [];
  var hasRelay;
  packet.js.paths.forEach(function(path){
    if(typeof path.type != "string") return;
    if(path.type == "relay" && packet.sender.type == "relay") return; // don't signal double-relay
    if(path.type.indexOf("ip") == 0 && isLocalIP(path.ip) && !peer.isLocal) return; // don't pass along local paths to public
    if(path.type == "relay") hasRelay = true;
    js.paths.push(path);
  });

  // look for a "viable" IP path between the two
  var viable = false;
  js.paths.forEach(function(path1){
    peer.paths.forEach(function(path2){
      if(path1.type != path2.type) return;
      if(path1.type.indexOf("ip") != 0) return; // only IP paths
      if(isLocalIP(path1.ip) != isLocalIP(path2.ip)) return; // must both be local or public
      viable = [path1,path2];
    });
  });
  debug("peer viable path results",JSON.stringify(viable));

  // when no viable path, always offer to bridge/relay
  if(!viable)
  {
    peer.bridging = true;
    js.paths.push({type:"bridge",id:packet.from.hashname,local:true});
    // add relay if none yet, and isn't via one already
    if(!hasRelay && packet.sender.type != "relay") js.paths.push({type:"relay", id:local.randomHEX(16)});
  }
  
  // must bundle the senders der so the recipient can open them
  peer.send({js:js, body:packet.from.der});
}

// packets coming in to me
function inRelayMe(err, packet, chan)
{
  if(err) return; // TODO clean up anything?
  if(!packet.body) return warn("relay in w/ no body",packet.js,packet.from.address);
  var self = packet.from.self;
  // create a network path that maps back to this channel
  var path = {type:"relay",id:chan.id,via:packet.from.hashname};
  self.receive(packet.body, path);
}

// proxy packets for two hosts
function inRelay(err, packet, chan)
{
  if(err) return;
  var self = packet.from.self;

  // new relay channel, validate destination
  if(!isHEX(packet.js.to, 64)) return warn("invalid relay of", packet.js.to, "from", packet.from.address);

  // if it's to us, handle that directly
  if(packet.js.to == self.hashname) return inRelayMe(err, packet, chan);

  // don't relay when it's coming from a relay
  if(packet.sender.type == "relay") return debug("ignoring relay request from a relay",packet.js.to,JSON.stringify(packet.sender));

  // if to someone else
  var to = self.whois(packet.js.to);
  if(to === packet.from) return warn("can't relay to yourself",packet.from.hashname);
  if(!to || !to.alive) return warn("relay to dead hashname", packet.js.to, packet.from.address);

  // throttle
  if(!packet.from.relayed || Date.now() - packet.from.relayed > 1000)
  {
    packet.from.relayed = Date.now();
    packet.from.relays = 0;
  }
  packet.from.relays++;
  if(packet.from.relays > 5) return debug("relay too fast, dropping",packet.from.relays);

  // dumb relay
  debug("relay middleman",packet.from.hashname,to.hashname);
  packet.from.relayed = Date.now();
  to.send(packet);
}

// return a see to anyone closer
function inSeek(err, packet, chan)
{
  if(err) return;
  if(!isHEX(packet.js.seek)) return warn("invalid seek of ", packet.js.seek, "from:", packet.from.address);
  var self = packet.from.self;
  var seek = packet.js.seek;

  var see = [];
  var seen = {};

  // see if we have any seeds to add
  var bucket = dhash(self.hashname, packet.js.seek);
  var links = self.buckets[bucket] ? self.buckets[bucket] : [];

  // first, sort by age and add the most wise one
  links.sort(function(a,b){ return a.age - b.age}).forEach(function(seed){
    if(see.length) return;
    if(!seed.seed) return;
    see.push(seed.address);
    seen[seed.hashname] = true;
  });

  // sort by distance for more
  links.sort(function(a,b){ return dhash(seek,a.hashname) - dhash(seek,b.hashname)}).forEach(function(link){
    if(seen[link.hashname]) return;
    if(link.seed || link.hashname.substr(seek.length) == seek)
    {
      see.push(link.address);
      seen[link.hashname] = true;
    }
  });

  var answer = {end:true, see:see.slice(0,8)};
  chan.send({js:answer});
}

// accept a dht link
function inLink(err, packet, chan)
{
  if(err) return;
  var self = packet.from.self;
  chan.timeout(defaults.nat_timeout);

  // send a response if this is a new incoming
  if(!chan.sentAt)
  {
    var js = {seed:self.seed};
    js.see = self.buckets[packet.from.bucket].sort(function(a,b){ return a.age - b.age }).filter(function(a){ return a.seed }).map(function(hn){ return hn.address }).slice(0,8);
    // add some distant ones if none
    if(!js.see.length) Object.keys(self.buckets).forEach(function(bucket){
      if(js.see.length >= 8) return;
      self.buckets[bucket].sort(function(a,b){ return a.age - b.age }).forEach(function(seed){
        if(js.see.length >= 8 || !seed.seed || js.see.indexOf(seed.address) != -1) return;
        js.see.push(seed.address);
      });
    });
    
    // TODO, check link_max and end it or evict another
    chan.send({js:js});
  }
  
  // look for any see and check to see if we should create a link
  if(Array.isArray(packet.js.see)) packet.js.see.forEach(function(address){
    var hn = self.whois(address);
    if(hn && self.buckets[hn.bucket].length < defaults.link_k) hn.link();
  });

  // add in this link
  if(!packet.from.age) packet.from.age = Date.now();
  packet.from.linked = chan;
  packet.from.seed = packet.js.seed;
  if(self.buckets[packet.from.bucket].indexOf(packet.from) == -1) self.buckets[packet.from.bucket].push(packet.from);
  
  // let mainteanance handle
  chan.callback = inMaintenance;
}

function inMaintenance(err, packet, chan)
{
  // ignore if this isn't the main link
  if(!packet.from || !packet.from.linked || packet.from.linked != chan) return;
  var self = packet.from.self;
  if(err)
  {
    delete packet.from.linked;
    var index = self.buckets[packet.from.bucket].indexOf(packet.from);
    if(index > -1) self.buckets[packet.from.bucket].splice(index,1);
    return;
  }

  // update seed status
  packet.from.seed = packet.js.seed;

  // only send a response if we've not sent one in a while
  if((Date.now() - chan.sentAt) > Math.ceil(defaults.link_timer/2)) chan.send({js:{seed:self.seed}});
}

// update/respond to network state
function inPath(err, packet, chan)
{
  debug("INPATH",JSON.stringify(packet.js));
  var self = packet.from.self;

  // check/try any alternate paths
  if(Array.isArray(packet.js.paths)) packet.js.paths.forEach(function(path){
    if(typeof path.type != "string") return; // invalid
    // don't send to ones we know about
    if(pathMatch(path, packet.from.paths)) return;
    // a new one, experimentally send it a path
    packet.from.raw("path",{js:{priority:1},to:path}, inPath);
    // stash any path for possible bridge
    packet.from.possible[path.type] = path;
  });
  
  // if path info from a seed, update our public ip/port
  if(packet.from.isSeed && typeof packet.js.path == "object" && packet.js.path.type == "ipv4" && !isLocalIP(packet.js.path.ip))
  {
    debug("updating public ipv4",self.address,JSON.stringify(packet.js.path));
    self.pathSet({type:"pub4", ip:packet.js.path.ip, port:parseInt(packet.js.path.port)})
    self.address = [self.hashname,packet.js.path.ip,parseInt(packet.js.path.port)].join(",");
  }
  
  // update any optional priority information
  if(typeof packet.js.priority == "number"){
    packet.sender.priority = packet.js.priority;
    if(packet.from.to && packet.sender.priority > packet.from.to.priority) packet.from.to = packet.sender; // make the default!    
  }

  if(err) return; // bye bye bye!
  
  // need to respond, prioritize everything above relay
  var priority = (packet.sender.type == "relay") ? 0 : 2;

  // if bridging, and this path is from the bridge, flag it for lower priority
  if(packet.from.bridge && pathMatch(packet.sender, self.whois(packet.from.bridge).paths)) priority = 1;

  chan.send({js:{end:true, priority:priority, path:packet.sender.json}});
}

// handle any bridge requests, if allowed
function inBridge(err, packet, chan)
{
  if(err) return;
  var self = packet.from.self;

  // ensure valid request
  if(!isHEX(packet.js.to,32) || !isHEX(packet.js.from,32) || typeof packet.js.path != "object") return warn("invalid bridge request",JSON.stringify(packet.js),packet.from.hashname);

  // must be allowed either globally or per hashname
  if(!self.bridging && !packet.from.bridging) return chan.send({js:{err:"not allowed"}});
  
  // special bridge path for local ips must be "resolved" to a real path
  if(packet.js.path.type == "bridge" && packet.js.path.local == true)
  {
    var local;
    var to = self.whois(packet.js.path.id);
    // just take the highest priority path
    if(to) to.paths.forEach(function(path){
      if(!local) local = path;
      if(path.priority > local.priority) local = path;
    });
    if(!local) return chan.send({js:{err:"invalid path"}});
    packet.js.path = local;
  }

  if(!packet.from.bridges) packet.from.bridges = {};
  packet.from.bridges[packet.js.to] = packet.from.bridges[packet.js.from] = true; // so we can clean up entries at some point

  // set up the actual bridge paths
  debug("BRIDGEUP",JSON.stringify(packet.js));
  self.bridges[packet.js.to] = packet.js.path;
  self.bridges[packet.js.from] = packet.sender;
  self.bridges[packet.js.to].via = self.bridges[packet.js.from].via = packet.from.hashname;

  chan.send({js:{end:true}});
}

// handle any bridge requests, if allowed
function inTS(err, packet, chan, callback)
{
  if(err) return;
  var self = packet.from.self;
  callback();

  // ensure valid request
  if(typeof packet.js.path != "string" || !self.TSockets[packet.js.path]) return chan.err("unknown path");
  
  // create the socket and hand back to app
  chan.wrap("TS");
  self.TSockets[packet.js.path](chan.socket);
  chan.send({js:{open:true}});
}

// type lan, looking for a local seed
function inLan(self, packet)
{
  if(packet.js.lan == self.lanToken) return; // ignore ourselves
  if(self.locals.length > 0) return; // someone locally is announcing already
  if(self.lanSkip == self.lanToken) return; // often immediate duplicates, skip them
  self.lanSkip = self.lanToken;
  // announce ourself as the seed back
  packet.js.type = "seed";
  self.send({type:"lan"}, local.pencode(packet.js, self.der));
}

// answers from any LAN broadcast notice we sent
function inLanSeed(self, packet)
{
  if(packet.js.lan != self.lanToken) return;
  if(self.locals.length >= 5) return warn("locals full");
  if(!packet.body || packet.body.length == 0) return;
  var der = local.der2der(packet.body);
  var to = self.whois(local.der2hn(der));
  if(!to) return warn("invalid lan request from",packet.sender);
  to.der = der;
  to.local = true;
  debug("local seed open",to.hashname,JSON.stringify(packet.sender));
  to.open(packet.sender);
}

// utility functions

// just return true/false if it's at least the format of a sha1
function isHEX(str, len)
{
  if(typeof str !== "string") return false;
  if(len && str.length !== len) return false;
  if(str.replace(/[a-f0-9]+/i, "").length !== 0) return false;
  return true;
}

// XOR distance between two hex strings, high is furthest bit, 0 is closest bit, -1 is error
function dhash(h1, h2) {
  // convert to nibbles, easier to understand
  var n1 = hex2nib(h1);
  var n2 = hex2nib(h2);
  if(!n1.length || !n2.length) return -1;
  // compare nibbles
  var sbtab = [-1,0,1,1,2,2,2,2,3,3,3,3,3,3,3,3];
  var ret = 252;
  for (var i = 0; i < n1.length; i++) {
    if(!n2[i]) return ret;
    var diff = n1[i] ^ n2[i];
    if (diff) return ret + sbtab[diff];
    ret -= 4;
  }
  return ret;
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

function pathMatch(path1, paths)
{
  var match;
  paths.forEach(function(path2){
    switch(path1.type)
    {
    case "ipv4":
    case "ipv6":
      if(path1.ip == path2.ip && path1.port == path2.port) match = path2;
      break;
    case "http":
      if(path1.http == path2.http) match = path2;
      break;
    case "bridge":
    case "relay":
    case "webrtc":
      if(path1.id == path2.id) match = path2;
      break;
    }
  });
  return match;
}

// validate if a network path is acceptable to stop at
function pathValid(path)
{
  if(!path || !path.lastIn) return false;
  if(Date.now() - path.lastIn < 60*1000) return true; // received anything in the last minute is good
  return false;
}


function partsMatch(parts1, parts2)
{
  if(typeof parts1 != "object" || typeof parts2 != "object") return false;
  var ids = Object.keys(parts1).sort(function(a,b){return b-a});
  var csid;
  while(csid = ids.shift()) if(parts2[csid]) return csid;
  return false;
}

// return if an IP is local or public
function isLocalIP(ip)
{
  // ipv6 ones
  if(ip.indexOf(":") >= 0)
  {
    if(ip.indexOf("::") == 0) return true; // localhost
    if(ip.indexOf("fc00") == 0) return true;
    if(ip.indexOf("fe80") == 0) return true;
    return false;
  }
  
  var parts = ip.split(".");
  if(parts[0] == "0") return true;
  if(parts[0] == "127") return true; // localhost
  if(parts[0] == "10") return true;
  if(parts[0] == "192" && parts[1] == "168") return true;
  if(parts[0] == "172" && parts[1] >= 16 && parts[1] <= 31) return true;
  if(parts[0] == "169" && parts[1] == "254") return true; // link local
  return false;
}
exports.isLocalIP = isLocalIP;

// our browser||node safe wrapper
})(typeof exports === 'undefined'? this['thjs']={}: exports);
