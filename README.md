telehash implemented in pure javascript
=======================================

Since telehash requires a real udp socket, there are various ways to use thjs in the browser:

* nodesocket - a minimal node.js service that bridges raw udp sockets to any browser over socket.io
* chromeapp - bindings to use the udp interface available to chrome apps

The crypto that powers this is only possible thanks to the incredible work done by the team behind [Forge](https://github.com/digitalbazaar/forge) and [Tom Wu](http://www-cs-students.stanford.edu/~tjw/).
