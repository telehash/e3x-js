var expect = require('chai').expect;
var e3x = require('../index.js');

describe('e3x', function(){

  // fixtures
  var pairs = {"1a":{"key":"0db0nke6w7ccev5zvv9xdqcgvbvj3328mm","secret":"e7b8a51ycbw8wdqpq81upr7p0kyp1rku"}};
  var remote = {"csid":"1a","key":"09h3xetda2erdxpc4nhv47ndx1y2akcjg8"};

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
      expect(pairs['1a'].key.length).to.be.equal(34);
      expect(pairs['1a'].secret.length).to.be.equal(32);
//      console.log("GEN",pairs);
      done();
    });
  });

  it('loads self', function(done){
    e3x.self({pairs:pairs}, function(err,self){
      expect(err).to.not.exist;
      expect(self).to.be.an('object');
      expect(self.decrypt).to.be.a('function');
      expect(self.exchange).to.be.a('function');
      done();
    });
  });

  it('creats an exchange', function(done){
    e3x.self({pairs:pairs}, function(err,self){
      self.exchange(remote, function(err, x){
        expect(err).to.not.exist;
        expect(x).to.be.an('object');
        expect(x.decrypt).to.be.a('function');
        expect(x.channel).to.be.a('function');
        expect(x.token.length).to.be.equal(16);
        done();
      });
    });
  });

});
