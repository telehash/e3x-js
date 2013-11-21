var udp = {};

var ab2str=function(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
};
var str2ab=function(str) {
  var buf=new ArrayBuffer(str.length);
  var bufView=new Uint8Array(buf);
  for (var i=0; i<str.length; i++) {
    bufView[i]=str.charCodeAt(i);
  }
  return buf;
}

function poll()
{
  var sock = this;
  chrome.socket.recvFrom(sock.id, 1500, function(msg){
    console.log("message",msg);
    if (msg.resultCode >= 0) {
      console.log("udp recv",msg.address,msg.port,msg.data.byteLength);
      if(sock.receive) sock.receive(ab2str(msg.data),{ip:msg.address,port:msg.port});
      sock.poll();
    } else {
      //poof
    }
  });
}

udp.create = function(cb)
{
  chrome.socket.create("udp", function(info){
    chrome.socket.bind(info.socketId, "0.0.0.0", 0, function(err){
      if(err) return chrome.socket.destroy(info.socketId) + cb();
      chrome.socket.getInfo(info.socketId, function(sock){
        sock.id = info.socketId;
        sock.poll = poll;
        sock.poll();
        sock.send = function(to, msg){
          console.log("udp send",to.ip,to.port,msg.length);
          chrome.socket.sendTo(sock.id, str2ab(msg), to.ip, parseInt(to.port), function(wi){
            console.log("sendTo",wi);
          });
        }
        cb(sock);
      })
    });
  }); 
}

