var dgram = require("dgram");
// UDP Server
var server = dgram.createSocket("udp4");
var address;

server.on("error", function (err) {
  console.log("server error:\n" + err.stack);
  server.close();
});

server.on("listening", function () {
  address = server.address();
  console.log("server listening " +
      address.address + ":" + address.port);
});

server.bind(8910, function() {});

// UDP Client
var client = dgram.createSocket("udp4");

var httpServer = require("http").createServer(function(req, resp) {
  req.url.replace("..",""); // this is super dumb minimal stub, don't actually use as a server
  var path = ".."+req.url;
  if(req.url == "/") path = "./socket.html";
    require("fs").readFile(path, "utf8", function(error, content) {
        resp.writeHeader(200, {"Content-Type": "text/html"});
        resp.end(content);
    });
}).listen(process.env.PORT || 8088);

var clients = [];
var io = require("socket.io").listen(httpServer);
io.sockets.on("connection", function (socket) {
  console.log("connected");
  socket.emit('connected', { ip: address.address, port: address.port });
  
  socket.on("listen", function(callback) {
    callback({data:(new Buffer("foo")).toString("base64")});
  });
  
  socket.on("message", function(data) {
    console.log("Received data from socket.io: " + data);
    packet = new Buffer(data.message, "base64");
    client.send(packet, 0, packet.length, data.port, data.ip, function(err, bytes) {
      console.log("Sent following msg to " + data.ip + ":" + data.port + " - " + data.message);
      client.close();
    });
  });
  
  server.on("message", function (msg, rinfo) {
    console.log("server got: " + msg + " from " + rinfo.address + ":" + rinfo.port)
    socket.emit("message", {message: msg, ip: rinfo.address, port: rinfo.port});
  });
});







/*

if(!process.argv[3])
{
  console.log("node test_packet.js host port");
  process.exit(1);
}

var client = dgram.createSocket("udp4");
var packet = encode({"hello":"world"}, "BODY");

if(process.argv[4])
{
  packet = new Buffer(process.argv[4], "hex");
}

client.send(packet, 0, packet.length, process.argv[3], process.argv[2], function(err, bytes) {
  console.log("sent",bytes,"bytes:",packet);
//  client.close();
});
client.on("message", function(msg, rinfo){
  console.log(rinfo, msg.toString("hex"));
})

function encode(js, body)
{
  var jsbuf = new Buffer(JSON.stringify(js), "utf8");
  if(typeof body === "string") body = new Buffer(body, "utf8");
  body = body || new Buffer(0);
  var len = new Buffer(2);
  len.writeInt16BE(jsbuf.length, 0);
  return Buffer.concat([len, jsbuf, body]);
}
*/

