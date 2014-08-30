var expect = require('chai').expect;
var e3x = require('../index.js');

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
  var handshakeBA = new Buffer('00045b32365d540140a402c56bb1237969bda478e6065863e0a31289ee808fec36903037cdd778badb7a7de7136519279977fbafffabef58f3ad','hex');

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

  it('loads self', function(done){
    e3x.self({pairs:pairsA}, function(err,self){
      expect(err).to.not.exist;
      expect(self).to.be.an('object');
      expect(self.decrypt).to.be.a('function');
      expect(self.exchange).to.be.a('function');
      done();
    });
  });

  it('creats an exchange', function(done){
    e3x.self({pairs:pairsA}, function(err,self){
      self.exchange({csid:'1a',key:pairsB['1a'].key}, function(err, x){
        expect(err).to.not.exist;
        expect(x).to.be.an('object');
        expect(x.decrypt).to.be.a('function');
        expect(x.channel).to.be.a('function');
        expect(x.token.length).to.be.equal(16);
        done();
      });
    });
  });

  it('generates a handshake', function(done){
    e3x.self({pairs:pairsA}, function(err,self){
      self.exchange({csid:'1a',key:pairsB['1a'].key}, function(err, x){
        var handshake = x.handshake();
//        console.log('HANDSHAKE',handshake.toString('hex'));
        expect(handshake).to.be.an('object');
        expect(handshake.length).to.be.equal(58);
        done();
      });
    });
  });

  it('creates a channel', function(done){
    e3x.self({pairs:pairsA}, function(err,self){
      self.exchange({csid:'1a',key:pairsB['1a'].key}, function(err, x){
        var c = x.channel(handshakeBA);
        expect(c).to.be.an('object');
        expect(c.send).to.be.a('function');
        expect(c.state).to.be.equal('opening')
        done();
      });
    });
  });

});
