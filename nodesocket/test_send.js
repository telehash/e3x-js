var dgram = require("dgram");

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
