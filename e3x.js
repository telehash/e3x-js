var crypto = require('crypto');
var lob = require('lob-enc');
var hashname = require('hashname');
var debug = require('debug')("E3X")
//var cbor = require('cbor');

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
        return cbDone(csid+': '+err);
      }
      pairs[csid] = pair;
      // async all done
      if(Object.keys(pairs).length == Object.keys(generators).length) return cbDone(undefined, pairs);
    });
  });
}

exports._generate = function(cbDone){

  // figure out which ciphersets have generators first
  var generators = {};
  Object.keys(csets).forEach(function(csid){
    if(!csets[csid] || !csets[csid].generate) return;
    generators[csid] = csets[csid]._generate;
  });
  if(!Object.keys(generators).length) return cbDone("no ciphersets");

  // async generate all of them
  var pairs = {};
  var errored;
  Object.keys(generators).forEach(function(csid){
    generators[csid]().then(function(pair){
      pairs[csid] = pair;
      // async all done
      if(Object.keys(pairs).length == Object.keys(generators).length) return cbDone(undefined, pairs);
    }).catch(cbDone);
  });
}

exports._self = function(args){
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
  self.locals[csid] = new csets[csid]._Local(args.pairs[csid]);
  exports.err = exports.err || self.locals[csid].err;
});
if(exports.err) return false;

// utilities
self.debug = debug;
self.decrypt = function(message)
{
  var csid = message.head.toString('hex');
  console.log(csid + " decrypt")

  return (typeof message != 'object'
          || !Buffer.isBuffer(message.body)
          || message.head.length != 1) ? Promise.reject(new Error("invalid message"))
       : (!self.locals[csid])          ? Promise.reject(new Error("unsupported Cipher Set"))
       : (self.locals[csid].decrypt(message.body).then(function(inner){
           var decoded = lob.decode(inner);
           if (!decoded) throw new Error("handshake invalid")
           return decoded;
         }));
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
    var cs = new csets[csid]._Remote(key);
    self.err = cs.err;
  }
  if(self.err) return false;

  var x = {csid:csid, key:key, cs:cs, isExchange:true, z:0};
  x.load = cs.load.then(function(){
    x.token = cs.token;
    x.id = args.id || cs.token.toString('hex'); // app can provide it's own unique identifiers;
  })

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

  //PROMISE
  x.verify = function(message){
    return cs.verify(self.locals[csid], message.body);
  };

  //PROMISE
  x.encrypt = function(inner){
    console.log("CSID", csid, self.locals[csid], self.locals)
    return cs.encrypt(self.locals[csid], inner)
              .then(function(body){
                console.log("encrypted", body)
                return lob.packet(csid1, body)
              });
  };

  //PROMISE
  x.receive = function(packet){
    if(!lob.isPacket(packet) || packet.head.length !== 0) return x.error('invalid packet');
    if(!x.session) return x.error('handshake sync required');
    return x.session.decrypt(packet.body.slice(16))
                    .then(lob.decode);
  };

  //PROMISE
  x.send = function(inner, arg){
    if(typeof inner != 'object') return Promise.reject(x.error('invalid inner packet'));
    if(!x.sending) return Promise.reject(x.error('send with no sending handler'));
    if(!x.session) return Promise.reject(x.error('send with no session'));

    inner = (!lob.isPacket(inner)) ? lob.packet(inner.json,inner.body) : inner; // convenience

    self.debug('channel encrypting',inner.json,inner.body.length);
    console.log("X.sending", x.sending.toString(), typeof x.sending)
    x.sending = (typeof x.sending == "function") ? x.sending : function noop(){};

    return x.load.then(function(){
      console.log("loaded")
       return x.session.encrypt(inner);
     }).then(function(enc){
       console.log("x.session.token", x.session.token)
       return lob.packet(null, Buffer.concat([x.session.token,enc]));
     })
     .then(function(packet){
       console.log("x.sending", x.sending.toString())
       x.sending(packet, arg);
       return packet;
     });
  };

  //PROMISE
  x.sync = function(handshake, inner){
    if(!handshake) return false;
    var getInner = (!inner) ? self.decrypt(handshake) : Promise.resolve(inner);
    return getInner.then(function(inner){
      return x.verify(handshake).then(function(ver){
       if (!ver)
         throw new Error("handshake failed to verify")

       var sid = handshake.slice(0,16).toString('hex'); // stable token  bytes
       if(x.sid != sid)
       {
         console.log("new ephemeral")
         x.session = new csets[csid]._Ephemeral(cs, handshake.body);
         x.sid = sid;
         x.z = parseInt(inner.z);
         // free up any gone channels since id's can be re-used now
         Object.keys(x.channels).forEach(function(id){
           if(x.channels[id].state == 'gone')
             delete x.channels[id];
         });
       }

       // make sure theirs is legit, or send a new one
       if((typeof inner.json.at != 'number') || (inner.json.at % 2 === 0 && x.order == 2))
         return false;

       // do nothing if we're in sync
       if(x._at === inner.json.at)
         return true;

       // if they're higher, save it as the best
       if(x._at < inner.json.at)
         x._at = inner.json.at;

       // signal to send a handshake
       return false;
     });
   });
  };

  // resend any packets we can
  x.flush = function(){
    Object.keys(x.channels).forEach(function(id){
      var chan = x.channels[id];
      // any open reliable channel, resend outq and trigger ack
      if(chan.reliable)
      {
        chan.outq.forEach(chan.ack);
        chan.ack();
      }else{
        // outgoing unreliable channels still opening, resend open
        if(chan.isOut && chan.state == 'opening') chan.send(chan.open);
      }
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

  // be handy handshaker
  // PROMISE
  x.handshake = function(inner){
    if(!inner)
    {
      // TODO deprecated
      inner = {};
      inner.body = hashname.key(csid, self.keys);
      inner.json = hashname.intermediates(self.keys);
      delete inner.json[csid]; // is implied here
      inner.json.type = 'key';
    }
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
      self.debug('no channel receiving handler',chan.type,chan.id);
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
      chan.inSeq = 1;
    }
    chan.inq = {}; // to order incoming packets for the app
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
      var packet = chan.inq[chan.inDone+1];
      // always force an ack when there's misses yet
      if(!packet && Object.keys(chan.inq).length > 0)
      {
        self.debug('packet missing seq',chan.inDone+1);
        chan.forceAck = true;
      }
      if(!packet)
      {
        self.debug('no more packets');
        chan.ack(); // auto-ack anything processed
        return;
      }
      if(chan.state != "open") return self.debug('no delivery to',chan.state); // paranoid
      delivering = true;
      // handle incoming ended, eventual cleanup
      if(packet.json.end === true){
        chan.state = "ended";
        cleanup();
      }
      chan.receiving(null, packet, function(err){
        if(err) return chan.fail(err);
        chan.inDone++;
        delete chan.inq[chan.inDone];
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
        chan.inq = {}; // delete all incoming
        chan.err = packet.json.err;
        chan.receiving(chan.err, packet, function(){});
        return cleanup();
      }

      chan.recvAt = Date.now();
      if(chan.state == "opening") chan.state = "open";

      // unreliable is easy, make our own sequence for the delivery flow
      if(!chan.reliable)
      {
        chan.inq[chan.inSeq] = packet;
        chan.inSeq++;
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
      var seq = parseInt(packet.json.seq);
      if(!(seq > 0)) return;

      // drop duplicate packets, always force an ack
      if(seq <= chan.inDone || chan.inq[seq]) return chan.forceAck = true;

      // drop if too far ahead, must ack
      if(seq-chan.inDone > defaults.chan_inbuf)
      {
        self.debug("chan too far behind, dropping", seq, chan.inDone, chan.id, x.id);
        return chan.forceAck = true;
      }

      // stash this seq and process any in sequence
      chan.inq[seq] = packet;
      self.debug("INQ",seq,Object.keys(chan.inq),chan.inDone,chan.startAt);
      deliver();
    }

    chan.send = function(packet){
      console.log("chan send begin")
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
        console.log("unreliable send")
        return x.send(lob.packet(packet.json,packet.body));
      }

      // add reliable tracking, make next one is highest
      if(!packet.json.seq) packet.json.seq = chan.outSeq;
      if(packet.json.seq >= chan.outSeq) chan.outSeq = packet.json.seq + 1;

      // reset/update tracking stats
      packet.sentAt = Date.now();
      if(chan.outq.indexOf(packet) == -1) chan.outq.push(packet);

      // add optional ack/miss and send
      chan.ack(packet);
      console.log('chan send end')
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
      var seen = Object.keys(chan.inq).sort(function(a,b){return a-b}); // numeric sort
      if(seen.length > 0)
      {
        packet.json.miss = [];
        // make sure ack is set, edge case
        if(!packet.json.ack) packet.json.ack = 0;
        var last = packet.json.ack;
        for(var i = seen[0]; i < seen[seen.length-1]; i++)
        {
          if(chan.inq[i]) continue;
          packet.json.miss.push(i - last);
          last = i;
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

    // resend the last sent packet if it wasn't acked
    chan.resend = function()
    {
      self.debug("resend check",chan.outq.length,chan.err);
      if(chan.err) return;
      if(!chan.outq.length) return;
      var lastpacket = chan.outq[chan.outq.length-1];
      // timeout force-end the channel
      var ago = Date.now() - lastpacket.sentAt;
      if(ago > chan.timeout)
      {
        if(chan.state != "ended") chan.receive(lob.packet({json:{err:"timeout",c:chan.id}}));
        return;
      }
      self.debug("channel resending",ago,chan.timeout);
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

    return chan;

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
