var expect = require('chai').expect;
var cs2a = require("../ciphers/2a/export.js");

describe('cs2a', function(){

  // fixtures
  var pairA = {key:new Buffer('30820122300d06092a864886f70d01010105000382010f003082010a0282010100d10101408daefea01e40757f1ff0ec89040fdd2f645d6e2012bf55b85406ca56ca93a089909c5c5eb8ae8e4031b04a126d3654ca78896843a70edb6171e56ff2a3a22d850b45817ffd9dddda7e0d461cf3a6e9bde2ff3abdb8876969011f94608146c6cb11ba5b936690b148c72bd2c10e53221a4b63a617babd3a674557d9f26a525dd60c98f7d5c3e01075318e56fa487c885a8b545e2a5117e9a1fa3dd864cba750b8e8814f37dba16b3148cad3726e96888157f9672b95ac945ad7748f48ca01b02efe9cb8f298ed2a8680a2c01dd33c03ca8909d9c1bf2dcfb7e3abef0f3c2966c3d8052d99f5f0731520ba2ec4c2121263ac9b5038d20d7b3943e6a5530203010001','hex'), secret:new Buffer('308204a30201000282010100d10101408daefea01e40757f1ff0ec89040fdd2f645d6e2012bf55b85406ca56ca93a089909c5c5eb8ae8e4031b04a126d3654ca78896843a70edb6171e56ff2a3a22d850b45817ffd9dddda7e0d461cf3a6e9bde2ff3abdb8876969011f94608146c6cb11ba5b936690b148c72bd2c10e53221a4b63a617babd3a674557d9f26a525dd60c98f7d5c3e01075318e56fa487c885a8b545e2a5117e9a1fa3dd864cba750b8e8814f37dba16b3148cad3726e96888157f9672b95ac945ad7748f48ca01b02efe9cb8f298ed2a8680a2c01dd33c03ca8909d9c1bf2dcfb7e3abef0f3c2966c3d8052d99f5f0731520ba2ec4c2121263ac9b5038d20d7b3943e6a5530203010001028201001dcc86e12d5245fb8e54a26bfda1dc17acfc960cabc2a670ec3b5b7d6c7d8b5bd48637dd6540e5ea9b6a47dddf37c357dd3a61dc7c531b0a8a47140050bce5b9329b6ce20b395dbd61eba03606c2ddbc43010952898ada55327a1c0d5c9ba40c1e6278f57b1196fced22b4242c41934af33fe71cd8a2dc8b8594753f4423c26f0bc2efa2b50e449d40f08cd292df0c075a2b3970ee79fce90ca37f88a79aaa8fd51c39a1579cbd2bd6e9b8a51ed60ef74c0811857a1b966366656690bb396d820478b17a9f6fbd91d68266673f144b241e3af07c3b786b28f1b2525c5637abd60b0dd876c49501170a732db68b1a3eef4e9a637e684294da7764534c93f6640102818100e9df261c2fda5a8b104ca4298b1d14de4ab1030bd0b787248098b19e86a56b2446a83fac3b2103e60f1e4a11b15c290e70cea4d40f06377d001387dd786c62320d2ceb9c6eb4c25782734933228a85475e91f09065a931210ff53a33fac6835aadc3bdc3516bb7cd00de404d868a01b4d5aaf1117af01c19b80fa8ca085177ef02818100e4c782178abec9b03f78be9ef23bcf15af423762ad29adbbe8b37cf0d8538ba63a253cf3a82b1f3fb6e16358cfac88b5a9a241fd9fb71e2ceb46486064038da6e70ee7fd0ebed7003c7f399bfc066a63598318baaff665155f91e5c56d9bb87af15beb817bc1a22ed53abde91d3c2cccec2320a4486faa8efc376461e213a4dd028181008bb56060ca3d58856671424806f0927cd085b9da1f0ee3ce6c7bcaef7663ef0336aa5f8f15ab7d56bb854e9e0f238ceb317c607ec592e326eb1abfb90fad3f63c2f728b0c4797af727d892cbd74084a9c3d6ceac93ee6488e9ad86dd725b903065495f5d0490a2b5f664ce69018c03c4f13732d74c678f81d5b095164badcf4502818070da194a139ed94e9f80a8472fa661188943589ecc5c6adeee82db76d2bf237bf3e2ba9656b62ecbf7226727400a13c5c8cfc94d9aa371b726b79cac2fa9b10e4b9c06c3c5aa4dd448035a1f9fca6a60679f4b6b8bb1375bbbb0f46ed70aa18dc3d15bf29b6180e72937b8c66d2d69cc0c0fa7e261f8f36164f8ce039ac9a5e10281806bf9600f714caa9d9506a6e234c4d83d016aa156365c77b967c4facd7559fdb3c8df73704407199c352820aa6a14c67ac19fbe899eadcb15254574a1281fac0b2d0622d726e8775d5f71c18b41ea443adaf06a8766bf9a80f8720eb4fc7b0f3db4ce47cb19c467876805ecc2e00ec14496ead4f47a0909970efa759d254d5882','hex')};
  var mbodyAB = new Buffer('44b0039aab2ef1483d93df3aff119bcbc2f35aa6f663dff4631cc581c356714ccb8ab278b639e602fd8b6aa1971f22293f9c235dc65605b1d5bae55fe9767f95b26ea72a4986b51795f60c7cce5d6384aae668cd9ce4c51f129902a9080a740015010335de6d17642b9a3e92e1651be758e921c066a24690997a7f8df08e2ff062929c30a198c1480b283ebf86a7287d3cd62989ce1f22fe7a97d8ef23303c44270b3ce96016eaf61ea587338f52e6caa107b5676e2a215d23f89a8cdd4247fb3172381a5753c3b5cfcf9fed26b3850f9a79fc38dbf13795301f135f9fcfe27733491d62d6d2c5f182334dce356267130e2779f8d295577603d3c597e49f1c324cb7907baba1cbbdad05cd5e87c9395f38f522585b96846cd257e864fc6c76296c197d17e15f29e028db26ea916b962732ac6571b297212ed322802f3d84d9c07c70173308ebd587ebf74cc9a233293c258a1c1b542ed711c39b5a141649af5004ea731358261abe4ae2d59e6c3a766713b4ef4023f057d4ec6dc58e2b8397a70f33b10b8e805e65fbdcdd52d8ad8aa90a8eb44d92e0a55343e65ff7d19f4d493c1d5f264f75a0c10d7e51994eb85c0bd2e8ac95685e5dd3664b175cae88ea788a475f47d1f35fbbc4c64a185636d9f83be39aee2476a66aebc5369d8c4fe9ee82a6c9cd106c5f27efa4da040248d6d9b19f42ace0bb698717aff3feb027cdda9e26d761b4b00b02d87d747594f4d3a13f802f1f0242fd7e9a950f50d25b','hex');

  var pairB = {key:new Buffer('30820122300d06092a864886f70d01010105000382010f003082010a0282010100cab6097c592ac9e6841676b33030c7f3aca4341efa3bce342f1a04ae81c1ac2fd400ed86c96b29ca05b59591a7d32db51aab19e564154ddcaadc8a8163a69990979ef318ad80bde23e666661f21c9c4e87a4e6974d8149584d5dc1136bdcb63ad4ef3ee2bb1472184ee03e95e7d5a8d16b17195beb968bb57393e58eb0d6cb3e2cc197a3f786c03b17a0acc9fe8245f6b72f264c13292d9d1b0988fbb8c6afd8afd503118b58e76d172dcb5d4ad6ed4b516afb5b994730bbb82adf1f90eb9d470abc045d805bfb9273def5eb0d42ba1c35d16cec0a49fc61558827bde162c89e6af92e1d1466e3ac5bbb52be078f721f4e5c97f22360aadf5b3545811ebef4710203010001','hex'), secret:new Buffer('308204a50201000282010100cab6097c592ac9e6841676b33030c7f3aca4341efa3bce342f1a04ae81c1ac2fd400ed86c96b29ca05b59591a7d32db51aab19e564154ddcaadc8a8163a69990979ef318ad80bde23e666661f21c9c4e87a4e6974d8149584d5dc1136bdcb63ad4ef3ee2bb1472184ee03e95e7d5a8d16b17195beb968bb57393e58eb0d6cb3e2cc197a3f786c03b17a0acc9fe8245f6b72f264c13292d9d1b0988fbb8c6afd8afd503118b58e76d172dcb5d4ad6ed4b516afb5b994730bbb82adf1f90eb9d470abc045d805bfb9273def5eb0d42ba1c35d16cec0a49fc61558827bde162c89e6af92e1d1466e3ac5bbb52be078f721f4e5c97f22360aadf5b3545811ebef47102030100010282010100ba2b5728e1c77f67faf59a8c54fce8166dfedc737ac3c44c7ed9b964ff7c7c83ec83f1a1b1887ef7b028a5b600d8dd088ff68630fbaae938799f548122a116360a5a0bcf2541b0a28146904ef209beb00cb9b0a152a823513ab499271a0fb938ece8d0eb707f858db79b113fa18cc39f9967bc7d842f5e1e0688d4f2288d0c58689c876faefb66faac349d7c3d80e80febe039b3e2c95546dde65c6d0657799a5ccea53be2ace83e35b746fa915119418bf89c3999ab758441acd9dd5c5a41ceaaac8487ae5f8412da055f47a198af8a6da0b864e1a765f33b6a91b4e8e9b53f7bf0c943a740229f583173bcee8dc53da9aead102c9e01c2673bcd58b4b6b42502818100f988f1e82f01ea6aabf95098dfbf25f00b70038442150945f3de4af51f829464c89acf183d88a73a59e49df64f3d2357dc809bec508e729f25e0219cd634590470b22518d0a9054adc670b757f626a2e9aa8a0ce5dcb2c13c9901e32409c7e44ec8993997750ffe7e1351b5767bd1ad022d9d4c8a2905e4fc2eef5d1098fcdcb02818100cff687b68a9dcf81980a25da4c591e546992da45348b710e490622a89a39a3e2b2faec36f5b0ddc29286920168c43d01f7c7888f04a5d834e52413656181548bd748ebf6a5d38ea3812119e214c5841b550f840bc470a915c8eb491426ac60fafc46b97af4bdf54b0d85ba4272f25907ad560c7f640b35a13a998b97cbdc3f33028181009a8c54b727161aa7c2a781618d8287eeaa46d006c41edf45720b0585d7e43a20499688194d532baf9a295c24476368566c7d431513b7860a479d0f7461bebe3b5fc915ecce9f4065e327f712e8b87d672be6b0e1df798c6d1cf3a3a020204c9c479bd5ccc0f76be7a3b60e9f0de3338e2167a4c036df0f6a7b2321203cb9d20d0281803febd6eb14d04ce7d883c5fec358e129b109a26d83291926faeb17dc1b0b7c8441df3e9be608e720d748e5b7e92be854a2848244f378c66bfbc28af3ae74c237f98440831f9557528a6e52365b8c1a7f0c3628b035412bb7b67a1b8c4616d5f84f72adb04d69d5ebabcc5ee3edd0efec9c2ac6cca14390c86deaa42d944bae610281810085fae4e832aa9717c00068dfb75b6a727bb0b08e3535f027f7644c7f435cd99ac79f518f110d6cf9ec8ec8eb0f1b0ffc0ae39ef57b5fa1b1db036028cc0a9d34810f7f137642eacace3ba777c664d2ec34402dfd856077249ad3e0d9820950d3c4583102eed59a5ccd225bc2557cc959b980b6058bda69f697bffb4086b21e38','hex')};
  var mbodyBA = new Buffer('8dd24cdabb9558bdb8bbb54afbfa93b70aa997e1ecc6520c8bccab6fad4d5d31c708069f425f0f9f9a6208e84b2e192f9fe4d342f5fefb655bd75298392246e6de8c6b7c7f8332cb3a0c88c2fd04c79b429289c1d92196d63c4e7e35624ad3d67564cc34ed3af6525a13fca268f2d07115f97f46e918f178f0b11027c681bd9f243fd6d81996aa625216d3d25356516a3b841ad0b730978a826e7537894eed1fa77ee47cfe0ddf9028bc1b8603bf934c50857ae98f7169cb9f6084327b1a9b0c5dcd6c9bf7adc6f86296110e6501833df4dc1a88e05209f410bec181344c9fcf527ba98ef451cfed3bf9e6c1d27d44ddf6cc123bd14745296287ecab885482ca049de7bdf423e0bed165f27ebdb9646c64cabe7626ab999fb7c4d8a757a934a862d0918cfb30ee52b76bc0211b7c8c19c0c6f06f4269daaac3bee0dfc5a1a3a73211a9b7c241800e2e7b041a269f4fcce6ff61850d95b54852004e951f57632bae2669a1ac931cfe96c275646d84a73342783cb8f63714b0fd7e313eb25e427447ca5905ce09fe0e30057b5ab25169c1c12efea2fd0743229a973c454cfbf52d88b3b310306ef4d99533211e2b859729374ce0d84e10badaadde5294355e59ad4b22888d9aafa3c0be843c714103632944c81bbb3a10b969941bc00ae1e624947aea12f3a0c679f68d09e1348cfcab55e0358962ce960ce92374c948bcc41d7691e5e17fa35cabd7dc3b162e661f45b1fff0b5c704877bc491541d3f70e0','hex');

  it('should export an object', function(){
    expect(cs2a).to.be.a('object');
  });

  it('should report id', function(){
    expect(cs2a.id).to.be.equal('2a');
  });

  it('should grow a pair', function(done){
    this.timeout(10000)
    cs2a.generate(function(err, pair){
      expect(err).to.not.exist;
      expect(pair).to.be.a('object');
      expect(Buffer.isBuffer(pair.key)).to.be.equal(true);
      expect(pair.key.length).to.be.equal(294);
      expect(Buffer.isBuffer(pair.secret)).to.be.equal(true);
      expect(pair.secret.length).to.be.above(1100);
      //console.log("KEY",pair.key.toString('hex'),"SECRET",pair.secret.toString('hex'));
      done(err);
    });
  });

  it('should load a pair', function(){
    var local = new cs2a.Local(pairA);
    expect(local).to.be.a('object');
    expect(local.err).to.not.exist;
    expect(local.decrypt).to.be.a('function');
  });

  it('should fail loading nothing', function(){
    var local = new cs2a.Local();
    expect(local.err).to.exist;
  });

  it('should fail with bad data', function(){
    var local = new cs2a.Local({key:new Buffer(21),secret:new Buffer(20)});
    expect(local.err).to.exist;
  });

  it('should local decrypt', function(){
    var local = new cs2a.Local(pairA);
    // created from remote encrypt
    var inner = local.decrypt(mbodyBA);
    expect(Buffer.isBuffer(inner)).to.be.equal(true);
    expect(inner.length).to.be.equal(2);
    expect(inner.toString('hex')).to.be.equal('0000');
  });

  it('should load a remote', function(){
    var remote = new cs2a.Remote(pairB.key);
    expect(remote.err).to.not.exist;
    expect(remote.verify).to.be.a('function');
    expect(remote.encrypt).to.be.a('function');
    expect(remote.token).to.exist;
    expect(remote.token.length).to.be.equal(16);
  });

  it('should local encrypt', function(){
    var local = new cs2a.Local(pairA);
    var remote = new cs2a.Remote(pairB.key);
    var message = remote.encrypt(local, new Buffer('0000','hex'));
    expect(Buffer.isBuffer(message)).to.be.equal(true);
    expect(message.length).to.be.equal(542);
    console.log("mbodyAB",message.toString('hex'));
  });

  it('should remote encrypt', function(){
    var local = new cs2a.Local(pairB);
    var remote = new cs2a.Remote(pairA.key);
    var message = remote.encrypt(local, new Buffer('0000','hex'));
    expect(Buffer.isBuffer(message)).to.be.equal(true);
    expect(message.length).to.be.equal(542);
    console.log("mbodyBA",message.toString('hex'));
  });

  it('should remote verify', function(){
    var local = new cs2a.Local(pairB);
    var remote = new cs2a.Remote(pairA.key);
    var bool = remote.verify(local, mbodyAB);
    expect(bool).to.be.equal(true);
  });

  it('should dynamically encrypt, decrypt, and verify', function(done){
    var local = new cs2a.Local(pairA);
    var remote = new cs2a.Remote(pairB.key);
    var inner = new Buffer('4242','hex');
    var outer = remote.encrypt(local, inner);
    console.log("outer", outer.toString("hex"))
    // now invert them to decrypt
    var local = new cs2a.Local(pairB);
    var remote = new cs2a.Remote(pairA.key);
    var inner2 = local.decrypt(outer);
    console.log("inner2", inner2)
    expect(inner2).to.exist;
    expect(inner2.toString('hex')).to.be.equal(inner.toString('hex'));

    // verify sender
    expect(remote.verify(local,outer)).to.be.equal(true);
    done();
  });

  it('should load an ephemeral', function(){
    var local = new cs2a.Local(pairA);
    var remote = new cs2a.Remote(pairB.key);
    expect(remote.verify(local, mbodyBA)).to.be.true;
    var ephemeral = new cs2a.Ephemeral(remote, mbodyBA);
    expect(ephemeral.decrypt).to.be.a('function');
    expect(ephemeral.encrypt).to.be.a('function');
  });

  it('ephemeral local encrypt', function(){
    var local = new cs2a.Local(pairA);
    var remote = new cs2a.Remote(pairB.key);
    expect(remote.verify(local, mbodyBA)).to.be.true;
    var ephemeral = new cs2a.Ephemeral(remote, mbodyBA);
    var channel = ephemeral.encrypt(new Buffer('0000','hex'));
    expect(Buffer.isBuffer(channel)).to.be.equal(true);
    expect(channel.length).to.be.equal(30);
  });

  it('ephemeral full', function(){
    // handshake one direction
    var localA = new cs2a.Local(pairA);
    var remoteB = new cs2a.Remote(pairB.key);
    var messageBA = remoteB.encrypt(localA, new Buffer('0000','hex'),1);

    // receive it and make ephemeral and reply
    var localB = new cs2a.Local(pairB);
    var remoteA = new cs2a.Remote(pairA.key);
    expect(remoteA.verify(localB, messageBA)).to.be.true;
    var ephemeralBA = new cs2a.Ephemeral(remoteA, messageBA);
    var messageAB = remoteA.encrypt(localB, new Buffer('0000','hex'),1);

    // make other ephemeral and encrypt
    expect(remoteB.verify(localA, messageAB)).to.be.true;
    var ephemeralAB = new cs2a.Ephemeral(remoteB, messageAB);
    var channelAB = ephemeralAB.encrypt(new Buffer('4242','hex'));

    // decrypt?
    var body = ephemeralBA.decrypt(channelAB);
    expect(ephemeralBA.err).to.not.exist;
    expect(Buffer.isBuffer(body)).to.be.equal(true);
    expect(body.length).to.be.equal(2);
    expect(body.toString('hex')).to.be.equal('4242');
  });

});

/*
// dummy functions
cs2a.install({pdecode:function(){console.log("pdecode",arguments);return {}},pencode:function(){console.log("pencode",arguments);return new Buffer(0)}});

var a = {parts:{}};
var b = {parts:{}};
cs2a.genkey(a,function(){
  console.log("genkey",a);
  cs2a.genkey(b,function(){
    console.log("genkey",b);
    var id = {cs:{"1a":{}}};
    cs2a.loadkey(id.cs["1a"],a["1a"],a["1a_secret"]);
    var to = {};
    cs2a.loadkey(to,b["1a"]);
    console.log(id,to);
    var open = cs2a.openize(id,to,{});
    console.log("opened",open);
  });
});
*/
