var crypto = require('crypto');
var lob = require('lob-enc');
var hashname = require('hashname');
var cbor = require('cbor');

var defaults = exports.defaults = {};
defaults.chan_timeout = 10000; // how long before for ending durable channels w/ no acks
defaults.chan_autoack = 1000; // is how often we auto ack if the app isn't generating responses in a durable channel
defaults.chan_resend = 2000; // resend the last packet after this long if it wasn't acked in a durable channel
defaults.chan_outbuf = 100; // max size of outgoing buffer before applying backpressure
defaults.chan_inbuf = 50; // how many incoming packets to cache during processing/misses

var csets = exports.cs = {};

exports.generate = function(cbDone){

  // figure out which ciphersets have generators first
  var generators = {};
  Object.keys(csets).forEach(function(csid){
    if(!csets[csid] || !csets[csid].generate) return;
    generators[csid] = csets[csid].generate;
  });
  if(!Object.keys(generators).length) return cbDone("no ciphersets");

  // async generate all of them
  var pairs = {};
  var errored;  
  Object.keys(generators).forEach(function(csid){
    generators[csid](function(err,pair){
      if(errored) return;
      if(err)
      {
        errored = true;
        return cbDone(err);
      }
      pairs[csid] = pair;
      // async all done
      if(Object.keys(pairs).length == Object.keys(generators).length) return cbDone(undefined, pairs);
    });
  });
}

exports.self = function(args){
  if(typeof args != 'object' || typeof args.pairs != 'object')
  {
    exports.err = 'invalid args';
    return false;
  }

  var self = {locals:{}, isSelf:true};
  self.args = args;
  self.keys = {};
  exports.err = undefined;
  Object.keys(csets).forEach(function(csid){
    if(!args.pairs[csid]) return;
    self.keys[csid] = args.pairs[csid].key;
    self.locals[csid] = new csets[csid].Local(args.pairs[csid]);
    exports.err = exports.err || self.locals[csid].err;
  });
  if(exports.err) return false;

  // utilities
  self.debug = args.debug||function(){console.log.apply(console, arguments);};

  self.decrypt = function(message)
  {
    if(typeof message != 'object' || !Buffer.isBuffer(message.body) || message.head.length != 1) return false;
    var csid = message.head.toString('hex');
    if(!self.locals[csid]) return false;
    var inner = self.locals[csid].decrypt(message.body);
    if(!inner) return false;
    return lob.decode(inner);
  }

  self.exchange = function(args)
  {
    if(typeof args != 'object' || !args.key) 
    {
      self.err = 'invalid args';
      return false;
    }
    var csid = (Buffer.isBuffer(args.csid)) ? args.csid.toString('hex') : args.csid;
    var csid1 = new Buffer(csid,'hex');
    var key = args.key;

    // generate the crypto backend handler
    if(!csets[csid])
    {
      self.err = 'no support for cs'+csid;
    }else{
      var cs = new csets[csid].Remote(key);
      self.err = cs.err;
    }
    if(self.err) return false;

    var x = {csid:csid, key:key, cs:cs, token:cs.token, isExchange:true, z:0};
    x.id = args.id || cs.token.toString('hex'); // app can provide it's own unique identifiers;
    // get our sort order by compairing the endpoint keys
    x.order = (bufsort(self.keys[csid],key) == key) ? 2 : 1;

    // set the channel id base and increment properly to be unique
    x.channels = {};
    var cid = x.order;
    x.cid = function(){
      var ret = cid;
      cid += 2;
      return ret;
    };
    
    // error wrapper
    x.error = function(err)
    {
      x.err = err;
      self.debug('exchange error',err);
      return false;
    }

    x.verify = function(message){
      return cs.verify(self.locals[csid], message.body);
    };

    x.encrypt = function(inner){
      var body = cs.encrypt(self.locals[csid], inner);
      if(!body) return false;
      return lob.packet(csid1,body);
    };

    x.receive = function(packet){
      if(!lob.isPacket(packet) || packet.head.length !== 0) return x.error('invalid packet');
      if(!x.session) return x.error('handshake sync required');
      var buf = x.session.decrypt(packet.body.slice(16));
      if(!buf) return x.error('decrypt failed: '+x.session.err);
      if(x.z == 1)
      {
        
      }else{
        var inner = lob.decode(buf);
      }
      return inner;
    };
    
    x.send = function(inner, arg){
      if(typeof inner != 'object') return x.error('invalid inner packet');
      if(!x.sending) return x.error('send with no sending handler');
      if(!x.session) return x.error('send with no session');
      if(!lob.isPacket(inner)) inner = lob.packet(inner.json,inner.body); // convenience
      self.debug('channel encrypting',inner.json,inner.body.length);
      if(x.z == 1)
      {
        self.debug('compressing w/ cbor');
        var zbuf = cbor.encode(inner.json.c);
        // TODO ...
      }
      var enc = x.session.encrypt(inner);
      if(!enc) return x.error('session encryption failed: '+x.session.err);
      // use senders token for routing
      var packet = lob.packet(null,Buffer.concat([x.session.token,enc]))
      if(typeof x.sending == 'function') x.sending(packet, arg);
      return packet;
    };

    x.sync = function(handshake, inner){
      if(!handshake) return false;
      if(!inner) inner = self.decrypt(handshake); // optimization to pass one in already done
      if(!inner) return false;
      if(!x.verify(handshake)) return false;

      // create/update session if needed
      var sid = handshake.slice(0,16).toString('hex'); // stable token bytes
      if(x.sid != sid)
      {
        var session = new csets[csid].Ephemeral(cs, handshake.body);
        if(session.err) return x.error('session error: '+session.err);
        self.debug('new ephemeral');
        x.session = session;
        x.sid = sid;
        x.z = parseInt(inner.z);
        // free up any gone channels since id's can be re-used now
        Object.keys(x.channels).forEach(function(id){
          if(x.channels[id].state == 'gone') delete x.channels[id];
        });
      }

      // make sure theirs is legit, or send a new one
      if(typeof inner.json.at != 'number') return false;
      if(inner.json.at % 2 === 0 && x.order == 2) return false;

      // do nothing if we're in sync
      if(x._at === inner.json.at) return true;

      // if they're higher, save it as the best
      if(x._at < inner.json.at) x._at = inner.json.at;
      
      // signal to send a handshake
      return false;
    };
    
    // resend any packets we can
    x.flush = function(){
      Object.keys(x.channels).forEach(function(id){
        var chan = x.channels[id];
        // outgoing channels still opening, resend open
        if(chan.isOut && chan.state == 'opening') chan.send(chan.open);
        // any open reliable channel, trigger ack
        if(chan.state == 'open' && chan.reliable) chan.ack();
      })
    }

    // set/return at
    x.at = function(at){
      if(at)
      {
        // make sure it's even/odd correctly
        if(x.order == 2)
        {
          if(at % 2 !== 0) at++;
        }else{
          if(at % 2 === 0) at++;
        }
        x._at = at; // cache it and to verify in return sync
      }
      return x._at;
    };
    // always start w/ now by default
    x.at(Math.floor(Date.now()/1000));

    x.handshake = function(){
      var inner = hashname.toPacket(self.keys,csid);
      delete inner.json[csid]; // is implied here
      inner.json.at = x._at;
      // TODO add .z = 1
      self.debug('handshake generated',x._at);
      return x.encrypt(lob.encode(inner));
    };
    
    x.channel = function(open){
      if(typeof open != 'object' || typeof open.json != 'object' || typeof open.json.type != 'string') return x.error('invalid open');
      
      // be friendly
      if(typeof open.json.c != 'number') open.json.c = x.cid();

      var chan = {state:'opening', open:open, isChannel:true};
      
      // stub handler, to be replaced by app
      chan.receiving = function(err, packet, cb){
        self.debug('no channel receiving handler');
        cb();
      }

      // reliable setup
      if(open.json.seq === 1)
      {
        chan.reliable = true;
        chan.outq = []; // to keep sent ones until ack'd
        chan.outSeq = 1; // to set outgoing json.seq
        chan.outConfirmed = 0; // highest outgoing json.seq that has been ack'd
        chan.lastAck = 0; // last json.ack that we've sent
      }else{
        chan.reliable = false;
      }
      chan.inq = []; // to order incoming packets for the app
      chan.inDone = 0; // highest incoming json.seq that has been done
      chan.type = open.json.type;
      chan.id = open.json.c;
      chan.startAt = Date.now();
      chan.isOut = (chan.id % 2 == x.order % 2);
      x.channels[chan.id] = chan; // track all active channels to route incoming packets

      // called to do eventual cleanup
      function cleanup()
      {
        if(chan.timer) clearTimeout(chan.timer);
        chan.timer = setTimeout(function(){
          chan.state = "gone"; // in case an app has a reference
          x.channels[chan.id] = {state:"gone"}; // remove our reference for gc
        }, chan.timeout);
      }

      // wrapper to deliver packets in series
      var delivering = false;
      function deliver()
      {
        if(delivering) return self.debug('delivering'); // one at a time
        if(chan.state != "open") return self.debug('not open'); // paranoid
        var packet = chan.inq[0];
        // always force an ack when there's misses yet
        if(!packet && chan.inq.length > 0)
        {
          self.debug('packet missing seq',chan.inDone+1);
          chan.forceAck = true;
        }
        if(!packet) return self.debug('no more packets');
        delivering = true;
        // handle incoming ended, eventual cleanup
        if(packet.json.end === true){
          chan.state = "ended";
          cleanup();
        }
        chan.receiving(null, packet, function(err){
          if(err) return chan.fail(err);
          chan.inq.shift();
          chan.inDone++;
          chan.ack(); // auto-ack
          delivering = false;
          deliver(); // iterate
        });
      }

      // process packets at a raw level, handle all miss/ack tracking and ordering
      chan.receive = function(packet)
      {
        // if it's an incoming error, bail hard/fast
        if(packet.json.err)
        {
          chan.inq = [];
          chan.err = packet.json.err;
          chan.receiving(chan.err, packet, function(){});
          return cleanup();
        }

        chan.recvAt = Date.now();
        if(chan.state == "opening") chan.state = "open";

        // unreliable is easy
        if(!chan.reliable)
        {
          chan.inq.push(packet);
          return deliver();
        }

        // process any valid newer incoming ack/miss
        var ack = parseInt(packet.json.ack);
        if(!ack > chan.outSeq) return self.debug("bad ack, dropping entirely",chan.outSeq,ack);
        var miss = Array.isArray(packet.json.miss) ? packet.json.miss : [];
        if(ack && (miss.length > 0 || ack > chan.lastAck))
        {
          self.debug("miss processing",ack,chan.lastAck,miss,chan.outq.length);
          // calculate the miss ids from the offsets
          var last = ack;
          miss = miss.map(function(id){
            last += id;
            return last;
          });
          if(last != ack) chan.missCap = last; // keep window size around to use for backpressure
          chan.lastAck = ack;
          // rebuild outq, only keeping newer packets, resending any misses
          var outq = chan.outq;
          chan.outq = [];
          outq.forEach(function(pold){
            // packet acknowleged!
            if(pold.json.seq <= ack) {
              if(pold.callback) pold.callback();
              if(pold.json.end) cleanup();
              return;
            }
            chan.outq.push(pold);
            if(miss.indexOf(pold.json.seq) == -1) return;
            // resend misses but not too frequently
            if(Date.now() - pold.resentAt < 1000) return;
            pold.resentAt = Date.now();
            chan.ack(pold);
          });
        }

        // don't process packets w/o a seq, no batteries included
        var seq = packet.json.seq;
        if(!(seq > 0)) return;

        // drop duplicate packets, always force an ack
        if(seq <= chan.inDone || chan.inq[seq-(chan.inDone+1)]) return chan.forceAck = true;

        // drop if too far ahead, must ack
        if(seq-chan.inDone > defaults.chan_inbuf)
        {
          self.debug("chan too far behind, dropping", seq, chan.inDone, chan.id, x.id);
          return chan.forceAck = true;
        }

        // stash this seq and process any in sequence, adjust for yacht-based array indicies
        chan.inq[seq-(chan.inDone+1)] = packet;
        self.debug("INQ",seq,Object.keys(chan.inq),chan.inDone,chan.startAt);
        deliver();
      }

      chan.send = function(packet){
        if(typeof packet != 'object') return self.debug('invalid send packet',packet);
        if(!packet.json) packet.json = {};
        packet.json.c = chan.id;

        // immediate fail errors
        if(packet.json.err)
        {
          if(chan.err) return self.debug('double-error',chan.err,packet.json.err); // don't double-error
          chan.err = packet.json.err;
          x.send(packet);
          return cleanup();
        }

        // unreliable just send straight away
        if(!chan.reliable)
        {
          return x.send(lob.packet(packet.json,packet.body));
        }

        // do reliable tracking
        if(!packet.json.seq) packet.json.seq = chan.outSeq++;

        // reset/update tracking stats
        packet.sentAt = Date.now();
        if(chan.outq.indexOf(packet) == -1) chan.outq.push(packet);

        // add optional ack/miss and send
        chan.ack(packet);

        return chan;
      };

      // add/create ack/miss values and send
      chan.ack = function(packet)
      {
        if(!chan.reliable)
        {
          if(packet) self.debug('dropping invalid ack packet for unreliable',packet);
          return;
        }
        if(!packet) self.debug('ack check',chan.id,chan.outConfirmed,chan.inDone);

        // these are just empty "ack" requests
        if(!packet)
        {
          // drop if no reason to ack so calling .ack() harmless when already ack'd
          if(!chan.forceAck && chan.outConfirmed == chan.inDone) return;
          packet = {json:{}};
        }
        chan.forceAck = false;

        // confirm only what's been processed
        if(chan.inDone) chan.outConfirmed = packet.json.ack = chan.inDone;

        // calculate misses, if any
        delete packet.json.miss; // when resending packets, make sure no old info slips through
        if(chan.inq.length > 0)
        {
          packet.json.miss = [];
          // make sure ack is set, edge case
          if(!packet.json.ack) packet.json.ack = 0;
          var last = packet.json.ack;
          for(var i = 0; i < chan.inq.length; i++)
          {
            if(chan.inq[i]) continue;
            packet.json.miss.push(chan.inq[i].seq - last);
            last = chan.inq[i].seq;
          }
          // push current buffer capacity
          packet.json.miss.push((packet.json.ack+defaults.chan_inbuf) - last);
        }

        // now validate and send the packet
        packet.json.c = chan.id;
        self.debug("rel-send",chan.type,JSON.stringify(packet.json),packet.body&&packet.body.length);

        if(chan.resender) clearTimeout(chan.resender);
        chan.resender = setTimeout(chan.resend, defaults.chan_resend);

        return x.send(lob.packet(packet.json,packet.body));
      }

      // configure default timeout, for resend
      chan.timeout = defaults.chan_timeout;
      chan.retimeout = function(timeout)
      {
        chan.timeout = timeout;
        // TODO reset any active timer
      }

      return chan;

      // resend the last sent packet if it wasn't acked
      chan.resend = function()
      {
        if(chan.ended) return;
        if(!chan.outq.length) return;
        var lastpacket = chan.outq[chan.outq.length-1];
        // timeout force-end the channel
        if(Date.now() - lastpacket.sentAt > arg.timeout)
        {
          hn.receive({js:{err:"timeout",c:chan.id}});
          return;
        }
        self.debug("channel resending");
        chan.ack(lastpacket);
        // continue until chan_timeout
        chan.resender = setTimeout(chan.resend, defaults.chan_resend);
      }

      // send error immediately, flexible arguments
      chan.fail = function(arg)
      {
        var err = "failed";
        if(typeof arg == "string") err = arg;
        if(typeof arg == "object" && arg.js && arg.js.err) err = arg.js.err;
        chan.send({err:err});
      }

    };
    
    return x;
  }

  return self;
}

function bufsort(a,b)
{
  for(var i=0;i<a.length;i++)
  {
    if(a[i] > b[i]) return a;
    if(b[i] > a[i]) return b;
  }
  return a;
}
