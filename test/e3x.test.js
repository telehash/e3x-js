var expect = require('chai').expect;
var e3x = require('../index.js');
var lob = require('lob-enc');

// convenience for handling buffer fixtures
function b2h(o)
{
  Object.keys(o).forEach(function(k){
    o[k] = o[k].toString('hex');
  });
  return o;
}
function h2b(o)
{
  Object.keys(o).forEach(function(k){
    o[k] = new Buffer(o[k],'hex');
  });
  return o;
}

describe('e3x', function(){

  // fixtures
  var pairsA = {"1a":h2b({"key":"03a3c4c9f6e081706be52903c75e077f0f3264eda1","secret":"12d2af807dd9cf8e3f99df395fac08dede4de913"})};
  var pairsB = {"1a":h2b({"key":"03fef52613c4dad0614d92cb7331d3e64658e0b8ba","secret":"a1e95d6a1bb247183b2f52f97c174a9fb39905d9"})};
  var handshakeAB = lob.decode(new Buffer('00011a036a8315f095fcfca8f903d51e350ae5edc10ae2c95cac38d695a475ec9f6e7809a1d4a4fd9c84b3826280ffcd5f9c5c2d2a5354e7f50a4b8b2f26ebd0cbb25bf3a71e2502','hex'));
  var handshakeBA = lob.decode(new Buffer('00011a0347ed6cf7cf3506ab69ab54499cd60940f8048c61148f1819228c3f5140790d2cd87d334c970e5614685d26c733a4f03ed0604cea9a4f27f41f7569145981755faa3989ff','hex'));

  it('should export an object', function(){
    expect(e3x).to.be.a('object');
  });

  it('should have cipher sets loaded', function(){
    expect(Object.keys(e3x.cs).length).to.be.equal(1);
  });

  it('generates keys', function(done){
    e3x.generate(function(err,pairs){
      expect(err).to.not.exist;
      expect(pairs).to.be.an('object');
      expect(Object.keys(pairs).length).to.be.above(0);
      expect(pairs['1a'].key.length).to.be.equal(21);
      expect(pairs['1a'].secret.length).to.be.equal(20);
//      console.log("GEN",JSON.stringify({'1a':b2h(pairs['1a'])}));
      done();
    });
  });

  it('loads self', function(){
    var self = e3x.self({pairs:pairsA});
    expect(e3x.err).to.not.exist;
    expect(self).to.be.an('object');
    expect(self.decrypt).to.be.a('function');
    expect(self.exchange).to.be.a('function');
  });

  it('creats an exchange', function(){
    var self = e3x.self({pairs:pairsA});
    var x = self.exchange({csid:'1a',key:pairsB['1a'].key});
    expect(self.err).to.not.exist;
    expect(x).to.be.an('object');
    expect(x.id).to.be.a('string');
    expect(x.send).to.be.a('function');
    expect(x.receive).to.be.a('function');
    expect(x.handshake).to.be.a('function');
    expect(x.sync).to.be.a('function');
    expect(x.channel).to.be.a('function');
    expect(x.token.length).to.be.equal(16);
    expect(x.order).to.be.equal(2);
  });

  it('does even odd', function(done){
    var self = e3x.self({pairs:pairsA});
    var x = self.exchange({csid:'1a',key:pairsB['1a'].key});
    x.handshake();
    expect(x._at % 2).to.be.equal(x.order?0:1)
    setTimeout(function(){
      var x = self.exchange({csid:'1a',key:pairsB['1a'].key});
      x.handshake();
      expect(x._at % 2).to.be.equal(x.order?0:1);
      done();
    },1000);
  });

  it('generates a handshake', function(){
    var self = e3x.self({pairs:pairsA});
    var x = self.exchange({csid:'1a',key:pairsB['1a'].key});
    var handshake = x.handshake();
//     console.log('handshakeAB',handshake.toString('hex'));
    expect(lob.isPacket(handshake)).to.be.true;
    expect(handshake.length).to.be.equal(72);
  });

  it('generates another handshake', function(){
    var self = e3x.self({pairs:pairsB});
    var x = self.exchange({csid:'1a',key:pairsA['1a'].key});
    var handshake = x.handshake();
//      console.log('handshakeBA',handshake.toString('hex'));
    expect(lob.isPacket(handshake)).to.be.true;
    expect(handshake.length).to.be.equal(72);
  });

  it('decode a handshake', function(){
    var self = e3x.self({pairs:pairsB});
    var inner = self.decrypt(handshakeAB);
    expect(inner).to.be.an('object');
    expect(inner.body.length).to.be.equal(21);
  });

  it('not decode a handshake', function(){
    var self = e3x.self({pairs:pairsA});
    var inner = self.decrypt(handshakeAB);
    expect(inner).to.not.exist;
  });

  it('verify a handshake', function(){
    var self = e3x.self({pairs:pairsB});
    var inner = self.decrypt(handshakeAB);
    var x = self.exchange({csid:'1a',key:inner.body});
    var c = x.verify(handshakeAB);
    expect(c).to.be.true;
  });

  it('require sync from a handshake', function(){
    var self = e3x.self({pairs:pairsB});
    var inner = self.decrypt(handshakeAB);
    var x = self.exchange({csid:'1a',key:inner.body});
    var at = x.sync(handshakeAB,{json:{}});
    expect(at).to.be.false;
  });

  it('be in sync from a handshake', function(){
    var self = e3x.self({pairs:pairsB});
    var inner = self.decrypt(handshakeAB);
    var x = self.exchange({csid:'1a',key:inner.body});
    x.at(1409417261); // force this so that it tests accepting the handshake
    var bool = x.sync(handshakeAB,{json:{at:1409417261}});
    expect(bool).to.be.true;
    // do it twice to make sure it's consistent
    var bool = x.sync(handshakeAB,{json:{at:1409417261}});
    expect(bool).to.be.true;
  });

  it('generate at, cache, and reset it', function(){
    var self = e3x.self({pairs:pairsB});
    var inner = self.decrypt(handshakeAB);
    var x = self.exchange({csid:'1a',key:inner.body});
    expect(x.at(1)).to.be.a('number');
    var bool = x.sync(handshakeAB,{json:{at:1409417262}});
    expect(bool).to.be.false;
    expect(x._at).to.be.equal(1409417262);
    expect(x.handshake()).to.exist;
    expect(x._at).to.be.equal(1409417262);
    expect(x.at(x.at())).to.be.equal(1409417263);
  });

  it('sends a channel packet', function(done){
    var self = e3x.self({pairs:pairsB});
    var inner = self.decrypt(handshakeAB);
    var x = self.exchange({csid:'1a',key:inner.body});
    x.sync(handshakeAB,{json:{}});
    x.sending = function(packet)
    {
      expect(lob.isPacket(packet)).to.not.be.false;
      done();
    }
    expect(x.send(lob.packet({c:42}))).to.not.be.false;
  });

  it('decrypts a channel packet', function(done){
    var selfA = e3x.self({pairs:pairsA});
    var xA = selfA.exchange({csid:'1a',key:pairsB['1a'].key});
    var hsAB = xA.handshake();

    var selfB = e3x.self({pairs:pairsB});
    var inner = selfB.decrypt(hsAB);
    var xB = selfB.exchange({csid:'1a',key:inner.body});
    var at = xB.sync(hsAB,inner);
    xA.sync(xB.handshake(at));
    xB.sending = function(packet)
    {
      expect(lob.isPacket(packet)).to.be.true;
      var inner = xA.receive(packet);
      expect(lob.isPacket(inner)).to.be.true;
      expect(inner.json.c).to.be.equal(42);
      done();
    }
    expect(xB.send(lob.packet({c:42}))).to.not.be.false;
  });

  it('creates an unreliable channel', function(){
    var self = e3x.self({pairs:pairsA});
    var x = self.exchange({csid:'1a',key:pairsB['1a'].key});
    x.sync(handshakeBA);
    var cid = x.cid();
    expect(cid).to.be.above(0);
    var c = x.channel({json:{c:cid,type:'test'}});
    expect(c).to.be.an('object');
    expect(c.reliable).to.be.false;
    expect(c.send).to.be.a('function');
    expect(c.state).to.be.equal('opening')
    expect(x.channels[c.id]).to.exist;
  });

  it('creates a reliable channel', function(){
    var self = e3x.self({pairs:pairsA});
    var x = self.exchange({csid:'1a',key:pairsB['1a'].key});
    x.sync(handshakeBA);
    var c = x.channel({json:{c:x.cid(),seq:1,type:'test'}});
    expect(c.reliable).to.be.true;
    expect(x.channels[c.id]).to.exist;
  });

  it('handles unreliable open', function(done){
    var self = e3x.self({pairs:pairsA});
    var x = self.exchange({csid:'1a',key:pairsB['1a'].key});
    x.sync(handshakeBA,{json:{}});
    var c = x.channel({json:{c:x.cid(),type:'test'}});
    c.receiving = function(err, packet, cb){
      expect(err).to.not.exist;
      expect(c.state).to.be.equal('open');
      expect(packet).to.be.an('object');
      expect(packet.json['42']).to.be.true;
      done();
    };
    c.receive({json:{'42':true}});
  });

  it('handles unreliable send', function(done){
    var self = e3x.self({pairs:pairsA});
    var x = self.exchange({csid:'1a',key:pairsB['1a'].key});
    x.sync(handshakeBA,{json:{}});
    x.sending = function(packet){
      expect(lob.isPacket(packet)).to.be.true;
      expect(packet.length).to.be.equal(49);
      expect(packet.head.length).to.be.equal(0);
      done();
    };
    var open = {json:{c:x.cid(),type:'test'}};
    var c = x.channel(open);
    c.send(open);
  });

  it('handles reliable open', function(done){
    var self = e3x.self({pairs:pairsA});
    var x = self.exchange({csid:'1a',key:pairsB['1a'].key});
    x.sync(handshakeBA,{json:{}});
    var open = {json:{c:x.cid(),seq:1,type:'test'}};
    var c = x.channel(open);
    c.receiving = function(err, packet, cb){
      expect(err).to.not.exist;
      expect(c.state).to.be.equal('open');
      expect(packet).to.be.an('object');
      expect(packet.json.seq).to.be.equal(1);
      done();
    };
    c.receive(open);
  });

  it('handles reliable send', function(done){
    var self = e3x.self({pairs:pairsA});
    var x = self.exchange({csid:'1a',key:pairsB['1a'].key});
    x.sync(handshakeBA,{json:{}});
    x.sending = function(buf){
      expect(Buffer.isBuffer(buf)).to.be.true;
      expect(buf.length).to.be.equal(57);
      done();
    };
    var open = {json:{c:x.cid(),seq:1,type:'test'}};
    var c = x.channel(open);
    c.send(open);
  });

  it('handles channel error', function(done){
    var self = e3x.self({pairs:pairsA});
    var x = self.exchange({csid:'1a',key:pairsB['1a'].key});
    x.sync(handshakeBA,{json:{}});
    var open = {json:{c:x.cid(),type:'test'}};
    var c = x.channel(open);
    c.send(open);
    c.send({json:{err:'bad'}});
    expect(c.err).to.be.equal('bad');
    done();
  });

});
