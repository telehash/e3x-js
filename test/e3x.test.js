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
  this.timeout(30000)
  // fixtures
  var pairsA = {"1a":h2b({"key":"03a3c4c9f6e081706be52903c75e077f0f3264eda1","secret":"12d2af807dd9cf8e3f99df395fac08dede4de913"})};
  var pairsB = {"1a":h2b({"key":"03fef52613c4dad0614d92cb7331d3e64658e0b8ba","secret":"a1e95d6a1bb247183b2f52f97c174a9fb39905d9"})};
  var handshakeAB = lob.decode(new Buffer('00011a036a8315f095fcfca8f903d51e350ae5edc10ae2c95cac38d695a475ec9f6e7809a1d4a4fd9c84b3826280ffcd5f9c5c2d2a5354e7f50a4b8b2f26ebd0cbb25bf3a71e2502','hex'));
  var handshakeBA = lob.decode(new Buffer('00011a0347ed6cf7cf3506ab69ab54499cd60940f8048c61148f1819228c3f5140790d2cd87d334c970e5614685d26c733a4f03ed0604cea9a4f27f41f7569145981755faa3989ff','hex'));

  it('should export an object', function(){
    expect(e3x).to.be.a('object');
  });

  it('should have cipher sets loaded', function(){
    expect(Object.keys(e3x.cs).length).to.be.equal(3);
  });

  it('generates keys', function(done){

    e3x.generate(function(err,pairs){
      expect(err).to.not.exist;
      console.log("pairs",pairs['1a'].key.length,pairs['2a'].key.length,pairs['3a'].key.length);
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

  it('creats an exchange', function(done){
    var self = e3x.self({pairs:pairsA});
    var x = self.exchange({csid:'1a',key:pairsB['1a'].key});
    x.load.then(function(){
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
      done()
    })

  });
  it('does even odd', function(done){
    var self = e3x.self({pairs:pairsA});
    var x = self.exchange({csid:'1a',key:pairsB['1a'].key});
    x.handshake()
     .then(function(){
       expect(x._at % 2).to.be.equal(x.order?0:1)
       setTimeout(function(){
         var x = self.exchange({csid:'1a',key:pairsB['1a'].key});
         x.handshake()
          .then(function(){
           expect(x._at % 2).to.be.equal(x.order?0:1);
           done();
          })
          .catch(function(e){
            throw e
          });
       },1000);
     })
     .catch(function (e){
       throw e;
     });

  });

  it('generates a handshake', function(done){
    var self = e3x.self({pairs:pairsA});
    var x = self.exchange({csid:'1a',key:pairsB['1a'].key});
    x.handshake()
     .then(function (handshake){
       expect(lob.isPacket(handshake)).to.be.true;
       expect(handshake.length).to.be.above(70);
       done()
     })
     .catch(function(e){
       console.log("generate handshake er", e, e.stack)
       throw e;
     });
//     console.log('handshakeAB',handshake.toString('hex'));
  });

  it('generates another handshake', function(done){
    var self = e3x.self({pairs:pairsB});
    var x = self.exchange({csid:'1a',key:pairsA['1a'].key});
    x.handshake()
     .then(function (handshake){

       expect(lob.isPacket(handshake)).to.be.true;
       expect(handshake.length).to.be.above(70);
       done()
     })
     .catch(function(e){
       throw e;
     });
  });

  it('decode a handshake', function(done){
    var self = e3x.self({pairs:pairsB});
    self.decrypt(handshakeAB)
        .then(function(inner){
          expect(Buffer.isBuffer(inner)).to.be.equal(true);
          expect(inner.body.length).to.be.equal(21);
          done()
        });
  });

  it('not decode a handshake', function(done){
    var self = e3x.self({pairs:pairsA});
    self.decrypt(handshakeAB)
        .then(function(res){
          console.log("this should fail",res)
        })
        .catch(function(){
          done()
        });
  });

  it('verify a handshake', function(done){
    var self = e3x.self({pairs:pairsB});
    self.decrypt(handshakeAB)
        .then(function(inner){
          return self.exchange({csid:'1a',key:inner.body}).verify(handshakeAB);
        }).then(function(c){
          expect(c).to.be.true;
          done()
        });;

  });

  it('require sync from a handshake', function(done){
    var self = e3x.self({pairs:pairsB});
    self.decrypt(handshakeAB)
        .then(function(inner){
          return self.exchange({csid:'1a',key:inner.body}).sync(handshakeAB,{json:{}})
        })
        .then(function (at){
          expect(at).to.be.false;
          console.log("GOT AT", !at)
          done()
        })
        .catch(function(er){
          console.log("require sync er", er, er.stack)
        });
  });

  it('be in sync from a handshake', function(done){
    var self = e3x.self({pairs:pairsB});
    var x;
    self.decrypt(handshakeAB)
        .then(function(inner){
          x = self.exchange({csid:'1a',key:inner.body})
          return x.at(1409417261);
        }).then(function(){
          return x.sync(handshakeAB,{json:{at:1409417261}});
        }).then(function(bool){
          expect(bool).to.be.true;
          return x.sync(handshakeAB,{json:{at:1409417261}})
        }).then(function(bool){
          expect(bool).to.be.true;
          done()
        });
  });

  it('generate at, cache, and reset it', function(done){
    var self = e3x.self({pairs:pairsB});
    var x;
    self.decrypt(handshakeAB)
        .then(function(inner){
          x = self.exchange({csid:'1a',key:inner.body})
          expect(x.at(1)).to.be.a('number');
          return x.sync(handshakeAB,{json:{at:1409417262}});
        })
        .then(function(bool){

          expect(bool).to.be.false;
          expect(x._at).to.be.equal(1409417262);
          return x.handshake();
        })
        .then(function(handy){
          expect(handy).to.exist;

          expect(x._at).to.be.equal(1409417262);
          expect(x.at(x.at())).to.be.equal(1409417263);
          done()
        });
  });

  it('sends a channel packet', function(done){
    var self = e3x.self({pairs:pairsB});
    var x;
    self.decrypt(handshakeAB)
        .then(function(inner){
          x = self.exchange({csid:'1a',key:inner.body});

          return x.sync(handshakeAB,{json:{}})
        })
        .then(function(){
          x.sending = function(packet){
            expect(lob.isPacket(packet)).to.not.be.false;
            done();
          }
          return x.send(lob.packet({c:42}));
        }).then(function(packet){
          expect(packet).to.not.be.false;
        });
  });

  it('decrypts a channel packet', function(done){
    var selfA = e3x.self({pairs:pairsA});
    var selfB = e3x.self({pairs:pairsB});
    var xA = selfA.exchange({csid:'1a',key:pairsB['1a'].key});
    xA.handshake()
      .then(function(hsAB){
        console.log("handshake", hsAB)
        var inner, xB;
        return selfB.decrypt(hsAB).then(function(inn){
          inner = inn;
          return selfB.exchange({csid:'1a',key:inner.body})
        }).then(function(x){
          xB = x;
          return xB.sync(hsAB, inner)
        }).then(function(at){
          return xB.handshake(at)
        }).then(function(hand){
          return xA.sync(hand)
        }).then(function(at){
          xB.sending = function(packet)
          {
            expect(lob.isPacket(packet)).to.be.true;
            xA.receive(packet)
              .then(function(inner){
                expect(lob.isPacket(inner)).to.be.true;
                expect(inner.json.c).to.be.equal(42);
                done();
              });

          }
          return xB.send(lob.packet({c:42}))
        }).then(function(res){
          expect(res).to.not.be.false;
        })
        .catch(function(er){
          console.log("error",er,er.stack)
        })
      }).catch(function(er){
        console.log("error", er, er.stack)
      })

  });

  it('creates an unreliable channel', function(done){
    var self = e3x.self({pairs:pairsA});
    var x = self.exchange({csid:'1a',key:pairsB['1a'].key});
    x.sync(handshakeBA)
      .then(function(at){
        var cid = x.cid();
        expect(cid).to.be.above(0);
        var c = x.channel({json:{c:cid,type:'test'}});
        expect(c).to.be.an('object');
        expect(c.reliable).to.be.false;
        expect(c.send).to.be.a('function');
        expect(c.state).to.be.equal('opening')
        expect(x.channels[c.id]).to.exist;
        done()
      });
  });

  it('creates a reliable channel', function(done){
    var self = e3x.self({pairs:pairsA});
    var x = self.exchange({csid:'1a',key:pairsB['1a'].key});
    x.sync(handshakeBA)
      .then(function(at){
        var c = x.channel({json:{c:x.cid(),seq:1,type:'test'}});
        expect(c.reliable).to.be.true;
        expect(x.channels[c.id]).to.exist;
        done()
      });
  });

  it('handles unreliable open', function(done){
    var self = e3x.self({pairs:pairsA});
    var x = self.exchange({csid:'1a',key:pairsB['1a'].key});
    x.sync(handshakeBA,{json:{}})
      .then(function(at){
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

  });

  it('handles unreliable send', function(done){
    var self = e3x.self({pairs:pairsA});
    var x = self.exchange({csid:'1a',key:pairsB['1a'].key});
    x.sync(handshakeBA,{json:{}})
      .then(function(at){
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
  });

  it('handles reliable open', function(done){
    var self = e3x.self({pairs:pairsA});
    var x = self.exchange({csid:'1a',key:pairsB['1a'].key});
    x.sync(handshakeBA,{json:{}})
      .then(function(at){
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

  });

  it('handles reliable send', function(done){
    var self = e3x.self({pairs:pairsA});
    var x = self.exchange({csid:'1a',key:pairsB['1a'].key});
    x.sync(handshakeBA,{json:{}})
      .then(function(at){
        x.sending = function(buf){
          x.sending = function(){}
          expect(Buffer.isBuffer(buf)).to.be.true;
          expect(buf.length).to.be.equal(57);
          done();
        };
        var open = {json:{c:x.cid(),seq:1,type:'test'}};
        var c = x.channel(open);
        c.send(open);
      });
  });

  it('handles channel error', function(done){
    var self = e3x.self({pairs:pairsA});
    var x = self.exchange({csid:'1a',key:pairsB['1a'].key});
    var c;
    x.sync(handshakeBA,{json:{}})
      .then(function(at){
        var open = {json:{c:x.cid(),type:'test'}};
        c = x.channel(open);
        x.sending = function(pack){

        }
        return c.send(open);
      }).then(function(){
        return c.send({json:{err:'bad'}});
      }).then(function(){
        expect(c.err).to.be.equal('bad');
        done();
      }).catch(function(er){
        console.log("er",er,er.stack)
      });

  });

});
