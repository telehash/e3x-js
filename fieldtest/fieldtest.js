var thjs = require("../thjs.js");
var self = thjs.switch();
require("telehash-cs1a").install(self);
console.log(self);
window.me = self;