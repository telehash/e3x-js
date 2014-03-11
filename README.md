telehash implemented in pure javascript
=======================================

This is now the core module to implement a [telehash](http://telehash.org) switch, other modules are required to enable it to support crypto and network interfaces.

If you're looking to use this in node or browserify, check out the npm [telehash](https://github.com/telehash/node-telehash) package (`npm install telehash`).  To see some example usage, try the [fieldtest](https://github.com/telehash/fieldtest) which works in node, browser, and as a chrome app.

## Modules

The `telehash` package in npm bundles most of these, but here's a list of all of the modules and where they work (please update when creating any)

* [seeds](https://github.com/telehash/telehash-seeds) - node, browser
* [cs1a](https://github.com/telehash/telehash-cs1a) - node, browser
* [cs2a](https://github.com/telehash/telehash-cs2a) - node, browser
* [cs3a](https://github.com/telehash/telehash-cs3a) - node
* [http](https://github.com/telehash/telehash-http) - node, browser
* [webrtc](https://github.com/telehash/telehash-webrtc) - browser
* [ipv4](https://github.com/telehash/telehash-ipv4) - node
* [ipv6](https://github.com/telehash/telehash-ipv6) - node

## API

This module exports one function called `switch` to create a new blank switch:

```js
var thjs = require("thjs");
var self = new thjs.switch();
```

A switch exposes the following methods:

* **self.load({keys})** - loads hashname from keys in the format `{"parts":{...}, "1a":"public base64", "1a_secret":"secret base64"}`
* **self.create(cbDone,cbStep)** - creates a new hashname, calls back `cbDone(err, keys)` when finished, and the optional `cbStep()` to show progress for slow systems
* **self.listen("type",cbListen)** - when a new incoming channel is requested for this type, pass it to `cbListen(err,packet,chan)`
* **self.start("hashname","type",{args},cbStart)** - creates a new outgoing channel of this type, calls `cbStart(err,packet,chan)`, args should include `"js":{...}` and optional `"body":Buffer`.
