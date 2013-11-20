telehash implemented in pure javascript
=======================================

Since telehash requires a real udp socket, there are various ways to use thjs in the browser:

* nodesocket - a minimal node.js service that bridges raw udp sockets to any browser over socket.io
* chromeapp - bindings to use the udp interface available to chrome apps

If you're looking to use this in node, check out the [node-telehash](https://github.com/telehash/node-telehash) package (in npm as just `telehash`).

To get a simple demo running using nodesocket as the backend, first run `npm install` to install the dependencies, then run `npm start` and in your browser go to http://localhost:8008/test/groupchat.html.  It should first generate a key (one time only) and then let you choose a nickname to create or join a rudimentary chatroom demo.  Use two different browsers to join/test multiple times.

The crypto that powers this is only possible thanks to the incredible work done by the team behind [Forge](https://github.com/digitalbazaar/forge) and [Tom Wu](http://www-cs-students.stanford.edu/~tjw/).
