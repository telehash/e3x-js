e3x: End-to-End Encrypted eXchange (javascript)
===============================================

[![Build Status](https://travis-ci.org/telehash/e3x-js.svg?branch=master)](https://travis-ci.org/telehash/e3x-js)

This module implements all of [e3x](https://github.com/telehash/telehash.org/tree/master/v3/e3x) in javascript as a node and browserify module.  It is used by [telehash-js](https://github.com/telehash/telehash-js) which is designed to provide a friendly higher level api, whereas this is low level and expects the application to manage all state tracking.

## Usage

All packets use [lob-enc](https://github.com/telehash/lob-enc) structure of: `{json:{...}, body:Buffer(...)}`

```js
var e3x = require('e3x');

var secrets = e3x.generate();

var self = e3x.self(args);
if(!self) console.log(e3x.err);

var inner = self.decrypt(message);
  
var exchange = self.exchange(args);
if(!exchange) console.log(self.err);

exchange.token; // 16 byte buffer
exchange.sending = function(packet){ }

var bool = exchange.verify(message);
var message = exchange.encrypt(inner);

var inner = exchange.receive(cpacket);

var at = exchange.at(at); // set the at, or return the current one if none given, will start to timeout channels until in sync
var bool = exchange.sync(handshake); // processes handshake to do all setup stuff, resends channels if in sync
var handshake = exchange.handshake(); // returns current handshake to be sent

var channel = exchange.channel(open);
if(!channel) console.log(exchange.err);

var bool = channel.receive(inner); // true if accepted
channel.send(packet); // calls exchange.sending()
channel.state;
channel.receiving = function(err, packet){};

```

## Cipher Sets

These are the current [Cipher Sets](https://github.com/telehash/telehash.org/tree/master/v3/e3x/cs) supported by default:

* [cs1a](https://github.com/quartzjer/e3x-cs1a) - node, browser
* [cs2a](https://github.com/quartzjer/telehash-cs2a) - node, browser
* [cs3a](https://github.com/quartzjer/telehash-cs3a) - node

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
var inner = ephemeral.decrypt(outer)


```
