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
    cs3a.generate(function(err, pair){
      expect(err).to.not.exist;
      expect(pair).to.be.a('object');
      expect(Buffer.isBuffer(pair.key)).to.be.equal(true);
      expect(pair.key.length).to.be.equal(32);
      expect(Buffer.isBuffer(pair.secret)).to.be.equal(true);
      expect(pair.secret.length).to.be.equal(32);
//      console.log("KEY",pair.key.toString('hex'),"SECRET",pair.secret.toString('hex'));
      done(err);
    });
  });

  it('should load a pair', function(){
    var local = new cs3a.Local(pairA);
    expect(local).to.be.a('object');
    expect(local.err).to.not.exist;
    expect(local.decrypt).to.be.a('function');
  });

  it('should fail loading nothing', function(){
    var local = new cs3a.Local();
    expect(local.err).to.exist;
  });

  it('should fail with bad data', function(){
    var local = new cs3a.Local({key:new Buffer(21),secret:new Buffer(20)});
    expect(local.err).to.exist;
  });

  it('should local decrypt', function(){
    var local = new cs3a.Local(pairA);
    // created from remote encrypt
    var inner = local.decrypt(mbodyBA);
    expect(Buffer.isBuffer(inner)).to.be.equal(true);
    expect(inner.length).to.be.equal(2);
    expect(inner.toString('hex')).to.be.equal('0000');
  });

  it('should load a remote', function(){
    var remote = new cs3a.Remote(pairB.key);
    expect(remote.err).to.not.exist;
    expect(remote.verify).to.be.a('function');
    expect(remote.encrypt).to.be.a('function');
    expect(remote.token).to.exist;
    expect(remote.token.length).to.be.equal(16);
  });

  it('should local encrypt', function(){
    var local = new cs3a.Local(pairA);
    var remote = new cs3a.Remote(pairB.key);
    var message = remote.encrypt(local, new Buffer('0000','hex'));
    expect(Buffer.isBuffer(message)).to.be.equal(true);
    expect(message.length).to.be.equal(90);
    console.log("mbodyAB",message.toString('hex'));
  });

  it('should remote encrypt', function(){
    var local = new cs3a.Local(pairB);
    var remote = new cs3a.Remote(pairA.key);
    var message = remote.encrypt(local, new Buffer('0000','hex'));
    expect(Buffer.isBuffer(message)).to.be.equal(true);
    expect(message.length).to.be.equal(90);
    console.log("mbodyBA",message.toString('hex'));
  });

  it('should remote verify', function(){
    var local = new cs3a.Local(pairB);
    var remote = new cs3a.Remote(pairA.key);
    var bool = remote.verify(local, mbodyAB);
    expect(bool).to.be.equal(true);
  });

  it('should dynamically encrypt, decrypt, and verify', function(done){
    var local = new cs3a.Local(pairA);
    var remote = new cs3a.Remote(pairB.key);
    var inner = new Buffer('4242','hex');
    var outer = remote.encrypt(local, inner);

    // now invert them to decrypt
    var local = new cs3a.Local(pairB);
    var remote = new cs3a.Remote(pairA.key);
    var inner2 = local.decrypt(outer);
    expect(inner2).to.exist;
    expect(inner2.toString('hex')).to.be.equal(inner.toString('hex'));

    // verify sender
    expect(remote.verify(local,outer)).to.be.equal(true);
    done();
  });

  it('should load an ephemeral', function(){
    var remote = new cs3a.Remote(pairB.key);
    var ephemeral = new cs3a.Ephemeral(remote, mbodyBA);
    expect(ephemeral.decrypt).to.be.a('function');
    expect(ephemeral.encrypt).to.be.a('function');
  });

  it('ephemeral local encrypt', function(){
    var remote = new cs3a.Remote(pairB.key);
    var ephemeral = new cs3a.Ephemeral(remote, mbodyBA);
    var channel = ephemeral.encrypt(new Buffer('0000','hex'));
    expect(Buffer.isBuffer(channel)).to.be.equal(true);
    expect(channel.length).to.be.equal(42);
  });

  it('ephemeral full', function(){
    // handshake one direction
    var localA = new cs3a.Local(pairA);
    var remoteB = new cs3a.Remote(pairB.key);
    var messageBA = remoteB.encrypt(localA, new Buffer('0000','hex'),1);

    // receive it and make ephemeral and reply
    var localB = new cs3a.Local(pairB);
    var remoteA = new cs3a.Remote(pairA.key);
    var ephemeralBA = new cs3a.Ephemeral(remoteA, messageBA);
    var messageAB = remoteA.encrypt(localB, new Buffer('0000','hex'),1);

    // make other ephemeral and encrypt
    var ephemeralAB = new cs3a.Ephemeral(remoteB, messageAB);
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
cs3a.install({pdecode:function(){console.log("pdecode",arguments);return {}},pencode:function(){console.log("pencode",arguments);return new Buffer(0)}});

var a = {parts:{}};
var b = {parts:{}};
cs3a.genkey(a,function(){
  console.log("genkey",a);
  cs3a.genkey(b,function(){
    console.log("genkey",b);
    var id = {cs:{"1a":{}}};
    cs3a.loadkey(id.cs["1a"],a["1a"],a["1a_secret"]);
    var to = {};
    cs3a.loadkey(to,b["1a"]);
    console.log(id,to);
    var open = cs3a.openize(id,to,{});
    console.log("opened",open);
  });
});
*/
