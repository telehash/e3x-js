telehash implemented in pure javascript
=======================================

This is now the core module to implement a [telehash](http://telehash.org) switch, other modules are required to enable it to support crypto and network interfaces.

If you're looking to use this in node or browserify, check out the npm [telehash](https://github.com/telehash/node-telehash) package (`npm install telehash`).  To see some example usage, try the [fieldtest](https://github.com/quartzjer/fieldtest) which works in node, browser, and as a chrome app.

## Modules

The `telehash` package in npm bundles most of these, but here's a list of all of the modules and where they work (please update when creating any)

* [seeds](https://github.com/Quartzjer/telehash-seeds) - node, browser
* [cs1a](https://github.com/Quartzjer/telehash-cs1a) - node, browser
* [cs2a](https://github.com/Quartzjer/telehash-cs2a) - node, browser
* [cs3a](https://github.com/Quartzjer/telehash-cs3a) - node
* [http](https://github.com/Quartzjer/telehash-http) - node, browser
* [webrtc](https://github.com/Quartzjer/telehash-webrtc) - browser
* [ipv4](https://github.com/Quartzjer/telehash-ipv4) - node
* [ipv6](https://github.com/Quartzjer/telehash-ipv6) - node

<a name="api" />
## Common API

This module exports one function called `switch` to create a new blank switch:

```js
var thjs = require("telehash-js");
var self = new thjs.switch();
```

The [telehash](https://github.com/telehash/node-telehash) provides it's own environment-friendly startup/init wrappers, and once you have a running switch it exposes the following methods:

* **self.listen("type",cbListen)** - when a new incoming channel is requested for this type, pass it to `cbListen(err,packet,chan)`
* **self.start("hashname","type",{args},cbStart)** - creates a new outgoing channel of this type, calls `cbStart(err,packet,chan)`, args should include `"js":{...}` and optional `"body":Buffer`.

Modules may extend this and provide additional API methods.

## Low Level API

A switch exposes the following core methods:

* **self.make(cbDone,cbStep)** - creates a new hashname id, calls back `cbDone(err, id)` when finished, and the optional `cbStep()` to show progress for slow systems
* **self.load({id})** - loads hashname from id in the format `{"parts":{...}, "1a":"public base64", "1a_secret":"secret base64"}`
* **self.addSeed({seed})** - adds info for a seed in the json format
* **self.online(cbOnline)** - turns this switch on, `cbOnline(err)`
* **self.whois(hashname)** - returns a hashname object (mostly for internal use)


