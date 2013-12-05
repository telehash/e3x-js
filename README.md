telehash implemented in pure javascript
=======================================

Since telehash requires a real udp socket, there are various ways to use thjs in the browser:

* nodesocket - a minimal node.js service that bridges raw udp sockets to any browser over socket.io
* chromeapp - bindings to use the udp interface available to chrome apps

If you're looking to use this in node, check out the [node-telehash](https://github.com/telehash/node-telehash) package (`npm install telehash`).

To get a simple demo running using nodesocket as the backend, first run `npm install` to install the test dependencies, then run `npm start` and in your browser go to http://localhost:8008/.  It should first generate a key (one time only) and then let you choose a nickname, then gives you a chat-style console to explore telehash.  Use two different browsers to create different instances to test with.

The crypto that powers this is only possible thanks to the incredible work done by the team behind [Forge](https://github.com/digitalbazaar/forge) and [Tom Wu](http://www-cs-students.stanford.edu/~tjw/).
