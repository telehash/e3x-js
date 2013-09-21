var httpServer = require("http").createServer(function(req, resp) {
  req.url.replace("..",""); // this is super dumb minimal stub, don't actually use as a server
  var path = ".."+req.url;
  if(req.url == "/") path = "./socket.html";
    require("fs").readFile(path, "utf8", function(error, content) {
        resp.writeHeader(200, {"Content-Type": "text/html"});
        resp.end(content);
    });
}).listen(process.env.PORT || 8080);

var clients = [];
var io = require("socket.io").listen(httpServer);
io.sockets.on("connection", function (socket) {
  console.log("connected");
  socket.on("listen", function(callback) {
    callback({data:(new Buffer("foo")).toString("base64")});
  });

});

