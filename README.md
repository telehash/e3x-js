e3x: End-to-End Encrypted eXchange (javascript)
===============================================

This module implements all of [e3x](https://github.com/telehash/telehash.org/tree/v3/v3/e3x) in javascript as a node and browserify module.  It is used by [telehash-js](https://github.com/telehash/node-telehash) which is designed to provide a friendly higher level api, whereas this is low level and expects the application to manage all state tracking.

## Usage

All packets use [lob-enc](https://github.com/quartzjer/lob-enc) structure of: `{json:{...}, body:Buffer(...)}`

```js
var e3x = require('e3x');

var secrets = e3x.generate();

e3x.self(opts,function(err,self){
  var inner = self.decrypt(message);
  
  self.exchange(opts,function(err,exchange){
    exchange.token; // 16 byte buffer
    exchange.sending = function(buffer){ }

    var bool = exchange.verify(message);
    var message = exchange.encrypt(inner);

    var inner = exchange.decrypt(cpacket);
    
    var bool = exchange.sync(handshake); // does setup stuff, resends or starts timing out channels
    var buffer = exchange.handshake();

    var channel = exchange.channel(opts, open);
    var bool = channel.receive(inner); // true if accepted
    channel.send(packet); // calls exchange.sending()
    channel.state;
    channel.receiving = function(err, packet){};
  });
});

```

## Cipher Sets

These are the current [Cipher Sets](https://github.com/telehash/telehash.org/tree/v3/v3/e3x/cs) supported by default:

* [cs1a](https://github.com/quartzjer/e3x-cs1a) - node, browser
* [cs2a](https://github.com/quartzjer/e3x-cs2a) - node, browser
* [cs3a](https://github.com/quartzjer/e3x-cs3a) - node

The API to implement a new CS module is just a simplified crypto wrapper:

```js
var cs = require('e3x-csxx');
cs.id; // 'xx';

cs.generate(cb); // new local keypair, cb(err, pair)

var local = new cs.Local(pair);
var inner = local.decrypt(body);

var remote = new cs.Remote(public_key_endpoint);
var bool = remote.verify(local, body);
var outer = remote.encrypt(local, inner);

var ephemeral = new cs.Ephemeral(remote, body);
var outer = ephemeral.encrypt(inner)
ver inner = ephemeral.decrypt(outer)


```
