function request(url, params, callback) {
  var xmlHttp = new XMLHttpRequest();
  xmlHttp.onreadystatechange = function() {
    if (xmlHttp.readyState == 4 && xmlHttp.status == 200)
      callback(xmlHttp.responseText);
  }
  var method = "GET"
  if (params) method = "POST"
  xmlHttp.open(method, url, true);
  if (method = "POST")
    xmlHttp.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
  xmlHttp.send(params);
}
function postClick(e) {
  console.log(e)
  e = e || window.event;
  if (e.target.className.indexOf("expando-button") == -1) { return }
  var targ = e.currentTarget || e.srcElement || e;
  if (targ.nodeType == 3) targ = targ.parentNode;
  var bdy = targ.getElementsByClassName("expando")[0]
  var btn = targ.getElementsByClassName("expando-button")[0]
  console.log(bdy.style.display)
  console.log(bdy.style.display.indexOf("block"))
  if (bdy.className.indexOf("open")>-1) {
    bdy.className = 'expando';
    btn.className = "expando-button"
  } else {
    bdy.className = 'expando open';
    btn.className = "expando-button open"
  }
}
function commentClick(e) {
  e = e || window.event;
  var targ = e.currentTarget || e.srcElement || e;
  if (targ.nodeType == 3) targ = targ.parentNode;
  if (e.target.name=="vote") {
    e.preventDefault()
    var form = e.target.parentNode
    if (form) {
      data = new FormData(form)
      if (("c"+data.get("commentid")) != targ.id) { return }
      params = new URLSearchParams(data).toString()
      params += "&" + e.target.name + "=" + e.target.value
      params += "&xhr=1"
      request(targ.target, params, function(res){
        targ.outerHTML = res
      })
    }
    return false
  }
  if (e.target.className.indexOf("minimize") != -1) {
    if (e.target.getAttribute("for") != targ.id) { return }
    e.preventDefault()
    var btn = targ.getElementsByClassName("minimize")[0]
    var children = targ.getElementsByClassName("children")[0]
    if (targ.className.indexOf("hidden") == -1) {
      targ.className = "comment hidden"
      btn.innerHTML = "[+]"
    } else {
      targ.className = "comment"
      btn.innerHTML = "[-]"
    }
    return false
  }
  if ((e.target.className.indexOf("loadmore") != -1) ||
    (e.target.className.indexOf("edit") != -1) ||
    (e.target.className.indexOf("source") != -1) ||
    (e.target.className.indexOf("reply") != -1)) {
    var id = targ.id
    if (e.target.getAttribute("for") != id) { return }
    e.preventDefault()
    request(e.target.href+"&xhr",false, function(res){
      targ.outerHTML = res
    })
    return false
  }
}
function formSubmit(e) {
  e = e || window.event;
  var targ = e.currentTarget || e.srcElement || e;
  console.log(e)
  e.preventDefault()
  var data = new FormData(targ)
  params = new URLSearchParams(data).toString()
  params += "&" + e.submitter.name + "=" + e.submitter.value
  params += "&xhr=1"
  request(targ.target, params, function(res){
    targ.outerHTML = res
  })
  return false
}
