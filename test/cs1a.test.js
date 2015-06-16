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
    cs1a.generate(function(err, pair){
      expect(err).to.not.exist;
      expect(pair).to.be.a('object');
      expect(Buffer.isBuffer(pair.key)).to.be.equal(true);
      expect(pair.key.length).to.be.equal(21);
      expect(Buffer.isBuffer(pair.secret)).to.be.equal(true);
      expect(pair.secret.length).to.be.equal(20);
//      console.log("KEY",pair.key.toString('hex'),"SECRET",pair.secret.toString('hex'));
      done(err);
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
    var inner = local.decrypt(mbodyBA);
    expect(Buffer.isBuffer(inner)).to.be.equal(true);
    expect(inner.length).to.be.equal(2);
    expect(inner.toString('hex')).to.be.equal('0000');
  });

  it('should load a remote', function(){
    var remote = new cs1a.Remote(pairB.key);
    expect(remote.verify).to.be.a('function');
    expect(remote.encrypt).to.be.a('function');
    expect(remote.token.length).to.be.equal(16);
  });

  it('should local encrypt', function(){
    var local = new cs1a.Local(pairA);
    var remote = new cs1a.Remote(pairB.key);
    var message = remote.encrypt(local, new Buffer('0000','hex'));
    expect(Buffer.isBuffer(message)).to.be.equal(true);
    expect(message.length).to.be.equal(31);
//    console.log("mbodyAB",message.toString('hex'));
  });

  it('should remote encrypt', function(){
    var local = new cs1a.Local(pairB);
    var remote = new cs1a.Remote(pairA.key);
    var message = remote.encrypt(local, new Buffer('0000','hex'));
    expect(Buffer.isBuffer(message)).to.be.equal(true);
    expect(message.length).to.be.equal(31);
//    console.log("mbodyBA",message.toString('hex'));
  });

  it('should remote verify', function(){
    var local = new cs1a.Local(pairB);
    var remote = new cs1a.Remote(pairA.key);
    var bool = remote.verify(local, mbodyAB);
    expect(bool).to.be.equal(true);
  });

  it('should dynamically encrypt, decrypt, and verify', function(){
    var local = new cs1a.Local(pairA);
    var remote = new cs1a.Remote(pairB.key);
    var inner = new Buffer('4242','hex');
    var outer = remote.encrypt(local, inner);

    // now invert them to decrypt
    var local = new cs1a.Local(pairB);
    var remote = new cs1a.Remote(pairA.key);
    expect(local.decrypt(outer).toString('hex')).to.be.equal(inner.toString('hex'));

    // verify sender
    expect(remote.verify(local,outer)).to.be.equal(true);
  });

  it('should load an ephemeral', function(){
    var remote = new cs1a.Remote(pairB.key);
    var ephemeral = new cs1a.Ephemeral(remote, mbodyBA);
    expect(ephemeral.decrypt).to.be.a('function');
    expect(ephemeral.encrypt).to.be.a('function');
  });

  it('ephemeral local encrypt', function(){
    var remote = new cs1a.Remote(pairB.key);
    var ephemeral = new cs1a.Ephemeral(remote, mbodyBA);
    var channel = ephemeral.encrypt(new Buffer('0000','hex'));
    expect(Buffer.isBuffer(channel)).to.be.equal(true);
    expect(channel.length).to.be.equal(10);
  });

  it('ephemeral full', function(){
    // handshake one direction
    var localA = new cs1a.Local(pairA);
    var remoteB = new cs1a.Remote(pairB.key);
    var messageBA = remoteB.encrypt(localA, new Buffer('0000','hex'),1);

    // receive it and make ephemeral and reply
    var localB = new cs1a.Local(pairB);
    var remoteA = new cs1a.Remote(pairA.key);
    var ephemeralBA = new cs1a.Ephemeral(remoteA, messageBA);
    var messageAB = remoteA.encrypt(localB, new Buffer('0000','hex'),1);

    // make other ephemeral and encrypt
    var ephemeralAB = new cs1a.Ephemeral(remoteB, messageAB);
    var channelAB = ephemeralAB.encrypt(new Buffer('4242','hex'));

    // decrypt?
    var body = ephemeralBA.decrypt(channelAB);
    expect(Buffer.isBuffer(body)).to.be.equal(true);
    expect(body.length).to.be.equal(2);
    expect(body.toString('hex')).to.be.equal('4242');
  });

});

/*
// dummy functions
cs1a.install({pdecode:function(){console.log("pdecode",arguments);return {}},pencode:function(){console.log("pencode",arguments);return new Buffer(0)}});

var a = {parts:{}};
var b = {parts:{}};
cs1a.genkey(a,function(){
  console.log("genkey",a);
  cs1a.genkey(b,function(){
    console.log("genkey",b);
    var id = {cs:{"1a":{}}};
    cs1a.loadkey(id.cs["1a"],a["1a"],a["1a_secret"]);
    var to = {};
    cs1a.loadkey(to,b["1a"]);
    console.log(id,to);
    var open = cs1a.openize(id,to,{});
    console.log("opened",open);
  });
});
*/
