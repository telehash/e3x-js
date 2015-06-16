Telehash Ciphers shared libraries
==============

Telehash leverages the work of [Forge](https://github.com/digitalbazaar/forge), [Tom Wu](http://www-cs-students.stanford.edu/~tjw/), and the [Stanford Javascript Crypto Library](https://github.com/bitwiseshiftleft/sjcl) to enable pure JS crypto.

sjcl and jsbn are both packaged as node modules and included via npm, but there are some incompatibilities with forge and browserify, so we include the minified forge library here.
