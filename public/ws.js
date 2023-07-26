var ok = false
var t = 800
var ws
var prot = location.protocol == 'https:' ? "wss://":"ws://"
let port = ":8009"

function start(){
  let url = prot + document.location.hostname + port + document.location.pathname + document.location.search;
  console.log('connecting to ', url);
  ws = new WebSocket(url);
  ws.onopen = function(){
    console.log("open");
    t = 800
  }
  ws.onmessage = function(msg){
    console.log("reload:", msg.data)
    if (msg.data == "") {
      return
    }
    window.location.reload()
  }
  ws.onclose = function(){
    console.log("close");
    setTimeout(function(){
      //start()
      if (t < 10 * 1000) t += 200
    }, t);
  };
}
console.log("ws");
if (typeof WebSocket != 'undefined') {
  start()
}
