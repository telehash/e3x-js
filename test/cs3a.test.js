var expect = require('chai').expect;
var cs3a = require("../ciphers/3a/export.js");

describe('cs3a', function(){

  // fixtures
  var pairA = {key:new Buffer('627f107c4c86d0f81cf6ad345b2a41b8ea29ae111db199c0fed547358ecb4257','hex'), secret:new Buffer('458fbd8b4964e29ed9f274c837055cc5f28ce37abe9cabf1869935c7a65da23b','hex')};
  var mbodyAB = new Buffer('ef60cc1a562d0cf7efef41fae16533ef238cc0feeb24ae6ca0bef3ec80c86b2a0fed311eac60b72c0286845ae34f6b746fb152d48d8f9a712fe411f9e4bef7a4ba806519740886711b47bbc29d6ab473b2de6892bf10465fb41d','hex');

  var pairB = {key:new Buffer('3d6062a1bb3549b56f8066f314574b5f444fe13f0b0c5cd0b5b95f12f09fd16c','hex'), secret:new Buffer('a117b27b21ac8bc39e53aeb552f4f4e92fd76856ef98985ebd1cc76612169d89','hex')};
  var mbodyBA = new Buffer('9019f4987aec555a4669b1c4ff6f7188bd94ce8c0a319b91c16328dbe57fab2e440dfc7dce24ad555eaafa566c73605a510ef5013a0331a2ca834b70d5fb39b3421e957364665ac2bda633ec89ff4b6921417f94b58b40f2b4cb','hex');

  it('should export an object', function(){
    expect(cs3a).to.be.a('object');
  });

  it('should report id', function(){
    expect(cs3a.id).to.be.equal('3a');
  });

  it('should grow a pair', function(done){
    cs3a.generate().then(function(pair){
      expect(pair).to.be.a('object');
      expect(Buffer.isBuffer(pair.key)).to.be.equal(true);
      expect(pair.key.length).to.be.equal(32);
      expect(Buffer.isBuffer(pair.secret)).to.be.equal(true);
      expect(pair.secret.length).to.be.equal(32);
//      console.log("KEY",pair.key.toString('hex'),"SECRET",pair.secret.toString('hex'));
      done();
    });
  });

  it('should load a pair', function(done){
    var local = new cs3a.Local(pairA);
    local.load.then(function(){
      expect(local).to.be.a('object');
      expect(local.err).to.not.exist;
      expect(local.decrypt).to.be.a('function');
      done()
    })

  });

  it('should fail loading nothing', function(){
    var local = new cs3a.Local();
    expect(local.err).to.exist;
  });

  it('should fail with bad data', function(){
    var local = new cs3a.Local({key:new Buffer(21),secret:new Buffer(20)});
    expect(local.err).to.exist;
  });

  it('should local decrypt', function(done){
    var local = new cs3a.Local(pairA);
    // created from remote encrypt
    local.decrypt(mbodyBA)
         .then(function(inner){
           expect(Buffer.isBuffer(inner)).to.be.equal(true);
           expect(inner.length).to.be.equal(2);
           expect(inner.toString('hex')).to.be.equal('0000');
           done()
         });

  });

  it('should load a remote', function(){
    var remote = new cs3a.Remote(pairB.key);
    expect(remote.err).to.not.exist;
    expect(remote.verify).to.be.a('function');
    expect(remote.encrypt).to.be.a('function');
    expect(remote.token).to.exist;
    expect(remote.token.length).to.be.equal(16);
  });

  it('should local encrypt', function(done){
    var local = new cs3a.Local(pairA);
    var remote = new cs3a.Remote(pairB.key);
    remote.encrypt(local, new Buffer('0000','hex'))
          .then(function(message){
            expect(Buffer.isBuffer(message)).to.be.equal(true);
            expect(message.length).to.be.equal(90);
            console.log("mbodyAB",message.toString('hex'));
            done()
          });

  });

  it('should remote encrypt', function(done){
    var local = new cs3a.Local(pairB);
    var remote = new cs3a.Remote(pairA.key);
    remote.encrypt(local, new Buffer('0000','hex'))
          .then(function(message){
            expect(Buffer.isBuffer(message)).to.be.equal(true);
            expect(message.length).to.be.equal(90);
            console.log("mbodyBA",message.toString('hex'));
            done()
          });

  });

  it('should remote verify', function(done){
    var local = new cs3a.Local(pairB);
    var remote = new cs3a.Remote(pairA.key);
    remote.verify(local, mbodyAB)
          .then(function(bool){
            expect(bool).to.be.equal(true);
            done()
          });
  });

  it('should dynamically encrypt, decrypt, and verify', function(done){
    var local = new cs3a.Local(pairA);
    var remote = new cs3a.Remote(pairB.key);
    var inner = new Buffer('4242','hex');
    var outer = remote.encrypt(local, inner);

   var local2 = new cs3a.Local(pairB);
   var remote2 = new cs3a.Remote(pairA.key);
   var outer
   return remote.encrypt(local, inner)
           .then(function(outerr){
             outer = outerr;
             return local2.decrypt(outer)
           })
           .then(function(inner2){
             return remote2.verify(local2, outer)
           })
           .then(function(verified){
             expect(verified).to.be.equal(true)
             done()
           })
           .catch(function(er){
             console.log("ER", er, er.stack)
           })

  });

  it('should load an ephemeral', function(done){
    var local = new cs3a.Local(pairA);
    var remote = new cs3a.Remote(pairB.key);
    remote.verify(local, mbodyBA)
          .then(function(ver){
            console.log
            expect(ver).to.be.true
            return ver;
          })
          .then(function(){
            var ephemeral =  new cs3a.Ephemeral(remote, mbodyBA);
            expect(ephemeral.decrypt).to.be.a('function');
            expect(ephemeral.encrypt).to.be.a('function');
            done()
          }).catch(function(er){
            console.log("ERR",er, er.stack)

          });
  });

  it('ephemeral local encrypt', function(done){
    var local = new cs3a.Local(pairA);
    var remote = new cs3a.Remote(pairB.key);
    remote.verify(local, mbodyBA)
          .then(function(ver){
            expect(ver).to.be.true
            return ver;
          })
          .then(function(){
            var ephemeral = new cs3a.Ephemeral(remote, mbodyBA);
            return ephemeral.encrypt(new Buffer("0000", "hex"));
          })
          .then(function(channel){
            expect(Buffer.isBuffer(channel)).to.be.equal(true);
            expect(channel.length).to.be.equal(42);
            return done()
          })
  });

  it('ephemeral full', function(){
    // handshake one direction
    var localA = new cs3a.Local(pairA);
    var remoteB = new cs3a.Remote(pairB.key);
    var localB = new cs3a.Local(pairB);
    var remoteA = new cs3a.Remote(pairA.key);
    var ephemeralBA, ephemeralAB, channelAB, messageBA, messageAB;
    remoteB.encrypt(localA, new Buffer('0000','hex'),1)
          .then(function(mBA){
            messageBA = mBA;
            return remoteA.verify(localB,messageBA)
          })
          .then(function(verified){
            expect(verified).to.be.true;
            return remoteA.encrypt(localB, new Buffer('0000','hex'),1 )
          })
          .then(function(mAB){
            messageAB = mAB
            return remoteB.verify(localA, messageAB)
          })
          .then(function(verified){
            expect(verified).to.be.true;
            ephemeralBA = new cs3a.Ephemeral(remoteA,messageBA)
            return remoteA.encrypt(localB,  new Buffer('0000','hex'),1)
          })
          .then(function(messageAB){
            return remoteB.verify(localA, messageAB)
          })
          .then(function(ver){
            expect(ver).to.be.true
            var ephemeralAB = new cs3a.Ephemeral(remoteB, messageAB)
            return ephemeralAB.encrypt(new Buffer('4242','hex'));
          }).then(function(cAB){
            channelAB = cAB;
            return ephemeralBA.decrypt(channelAB)
          })
          .then(function(body){
            expect(ephemeralBA.err).to.not.exist;
            expect(Buffer.isBuffer(body)).to.be.equal(true);
            expect(body.length).to.be.equal(2);
            expect(body.toString('hex')).to.be.equal('4242');
            done()
          })
  });

});
