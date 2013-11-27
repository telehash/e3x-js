window.onload = load;

function load()
{
  console.log("loaded");
  thforge.forge(forge);
  thjs.debug(function(){console.log.apply(console,arguments)});
  getId(function(id){
    udp.create(function(sock){
      if(!sock) return;
      console.log(sock,id);
    	me = thjs.hashname(id, function(to, msg) {
        console.log("sending", to.hashname, msg.length());
        sock.send(to, msg.bytes());
      });
      // every 10 sec update local IP
      function locals(){
        sock.setLocal(me);
        setTimeout(locals, 10000);
      }
      locals();
      sock.receive = function(msg,from){me.receive(msg,from)};
    	console.log("switch created",me);
      document.querySelector("#hashname").innerHTML = me.hashname;
			seeds.forEach(me.addSeed, me);
			me.online(function(err,to){
			  console.log("online",err,to&&to.hashname);
        document.querySelector("#online").innerHTML = err||"online";
      })
    });
  });
}

function getId(callback)
{
	chrome.storage.local.get(["public","private"], function(id){
	  if(id.public) return callback(id);
    thforge.genkey(function(err, id){
      chrome.storage.local.set(id);
      callback(id);
    });
	});
}