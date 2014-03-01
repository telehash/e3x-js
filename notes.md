# Networking API

With a created switch, you must register network types for delivery:

```js
var s = thjs.hashname(id);
s.deliver("http",function(path,msg,to){ ...send msg to the given path... });
s.receive(msg, path);
```
