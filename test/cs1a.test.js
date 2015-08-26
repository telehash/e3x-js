var expect = require('chai').expect;
var cs1a = require("../ciphers/1a/export.js");

describe('cs1a', function(){

  // fixtures
  var pairA = {key:new Buffer('03be277f53630a084de2f39c7ff9de56c38bb9d10c','hex'), secret:new Buffer('792fd655c8e03ae16e0e49c3f0265d04689cbea3','hex')};
  var mbodyAB = new Buffer('030d8def4405c1380afeca3760322be710a3f53cfe7c9bed207249f31af977','hex');

  var pairB = {key:new Buffer('0365694904381c00dfb7c01bb16b0852ea584a1b0b','hex'), secret:new Buffer('031b502b0743b80c1575f4b459792b5d76ad636d','hex')};
  var mbodyBA = new Buffer('021aaad76e86b2c951a0ab00b22d031567b6bd556aa953a22b65f5d62dcbba','hex');

  it('should export an object', function(){
    expect(cs1a).to.be.a('object');
  });

  it('should report id', function(){
    expect(cs1a.id).to.be.equal('1a');
  });

  it('should grow a pair', function(done){
    cs1a.generate().then(function(pair){
      console.log("GOT KEY", Buffer.isBuffer(pair.key), Buffer.isBuffer(pair.secret), pair.key.length, pair.secret.length)
      expect(pair).to.be.a('object');
      expect(Buffer.isBuffer(pair.key)).to.be.equal(true);
      expect(pair.key.length).to.be.equal(21);
      expect(Buffer.isBuffer(pair.secret)).to.be.equal(true);
      expect(pair.secret.length).to.be.equal(20);
      done();
    });
  });

  it('should load a pair', function(){
    var local = new cs1a.Local(pairA);
    expect(local).to.be.a('object');
    expect(local.err).to.not.exist;
    expect(local.decrypt).to.be.a('function');
  });

  it('should fail loading nothing', function(){
    var local = new cs1a.Local();
    expect(local.err).to.exist;
  });

  it('should fail with bad data', function(){
    var local = new cs1a.Local({key:new Buffer(Array(21)),secret:new Buffer(Array(20))});
    expect(local.err).to.exist;
  });

  it('should local decrypt', function(){
    var local = new cs1a.Local(pairA);
    // created from remote encrypt
    local.decrypt(mbodyBA)
         .then(function(inner){

            expect(Buffer.isBuffer(inner)).to.be.equal(true);
            expect(inner.length).to.be.equal(2);
            expect(inner.toString('hex')).to.be.equal('0000');
         });
  });

  it('should load a remote', function(){
    var remote = new cs1a.Remote(pairB.key);
    expect(remote.verify).to.be.a('function');
    expect(remote.encrypt).to.be.a('function');
    expect(remote.token.length).to.be.equal(16);
  });

  it('should local encrypt', function(done){
    var local = new cs1a.Local(pairA);
    var remote = new cs1a.Remote(pairB.key);
    remote.encrypt(local, new Buffer('0000','hex'))
          .then(function(message){
            expect(Buffer.isBuffer(message)).to.be.equal(true);
            expect(message.length).to.be.equal(31);
            done()
          });
  });

  it('should remote encrypt', function(done){
    var local = new cs1a.Local(pairB);
    var remote = new cs1a.Remote(pairA.key);
    remote.encrypt(local, new Buffer('0000','hex'))
          .then(function(message){
            expect(Buffer.isBuffer(message)).to.be.equal(true);
            expect(message.length).to.be.equal(31);
            done()
          });
  });

  it('should remote verify', function(done){
    var local = new cs1a.Local(pairB);
    var remote = new cs1a.Remote(pairA.key);
    remote.verify(local, mbodyAB)
          .then(function(bool){
              expect(bool).to.be.equal(true);
              done()
          });

  });

  it('should dynamically encrypt, decrypt, and verify', function(done){
    var local = new cs1a.Local(pairA);
    var remote = new cs1a.Remote(pairB.key);
    var inner = new Buffer('4242','hex');

    remote.encrypt(local, inner)
          .then(function(out){
            outer = out;

            local = new cs1a.Local(pairB);
            remote = new cs1a.Remote(pairA.key);
            return local.decrypt(out);
          })
          .then(function(inn){
            expect(inn.toString("hex")).to.be.equal(inner.toString('hex'))
            return remote.verify(local,outer)
          })
          .then(function(bool){
            expect(bool).to.be.equal(true);
            done()
          })

  });

  it('should load an ephemeral', function(){
    var remote = new cs1a.Remote(pairB.key);
    var ephemeral = new cs1a.Ephemeral(remote, mbodyBA);
    expect(ephemeral.decrypt).to.be.a('function');
    expect(ephemeral.encrypt).to.be.a('function');
  });

  it('ephemeral local encrypt', function(done){
    var remote = new cs1a.Remote(pairB.key);
    var ephemeral = new cs1a.Ephemeral(remote, mbodyBA);
    ephemeral.encrypt(new Buffer('0000','hex'))
             .then(function(channel){
               expect(Buffer.isBuffer(channel)).to.be.equal(true);
               expect(channel.length).to.be.equal(10);
               done()
             });
  });

  it('ephemeral full', function(done){
    // handshake one direction
    var localA = new cs1a.Local(pairA);
    var remoteB = new cs1a.Remote(pairB.key);


    var localB = new cs1a.Local(pairB);
    var remoteA = new cs1a.Remote(pairA.key);

    var ephemeralBA, ephemeralAB, channelAB;

    remoteB.encrypt(localA, new Buffer('0000','hex'),1)
           .then(function(messageBA){
             ephemeralBA = new cs1a.Ephemeral(remoteA, messageBA);
             return remoteA.encrypt(localB, new Buffer('0000','hex'),1)
           })
           .then(function(messageAB){

             ephemeralAB = new cs1a.Ephemeral(remoteB, messageAB);
             return ephemeralAB.encrypt(new Buffer("4242","hex"));
           })
           .then(function(chan){
             channelAB = chan;
             return ephemeralBA.decrypt(channelAB);
           })
           .then(function(body){

             expect(Buffer.isBuffer(body)).to.be.equal(true);
             expect(body.length).to.be.equal(2);
             expect(body.toString('hex')).to.be.equal('4242');
             done()
           });

    // receive it and make ephemeral and reply
      /*
    var messageAB = remoteA.encrypt(localB, new Buffer('0000','hex'),1);

    // make other ephemeral and encrypt
    var ephemeralAB = new cs1a.Ephemeral(remoteB, messageAB);
    var channelAB = ephemeralAB.encrypt(new Buffer('4242','hex'));

    // decrypt?
    var body = ephemeralBA.decrypt(channelAB);
    */
  });

});
