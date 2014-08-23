e3x: End-to-End Encrypted eXchange (javascript)
===============================================

This module implements all of [e3x](https://github.com/telehash/telehash.org/tree/v3/v3/e3x) in javascript as a node and browserify module.  It is used by [telehash-js](https://github.com/telehash/node-telehash) which is designed to provide a friendly higher level api, whereas this is low level and expects the application to manage all state tracking.

## Usage

```js
var e3x = require('e3x');
var self = new e3x.Self(keys, secrets);

```

## Cipher Sets

These are the current [Cipher Sets](https://github.com/telehash/telehash.org/tree/v3/v3/e3x/cs) supported by default:

* [cs1a](https://github.com/quartzjer/e3x-cs1a) - node, browser
* [cs2a](https://github.com/quartzjer/e3x-cs2a) - node, browser
* [cs3a](https://github.com/quartzjer/e3x-cs3a) - node

The API to implement a new CS module is:

```js

```