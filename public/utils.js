function request(url, params, callback, errorcallback) {
  var xmlHttp = new XMLHttpRequest();
  xmlHttp.onreadystatechange = function() {
    if (xmlHttp.readyState == 4 && xmlHttp.status == 200)
      return callback(xmlHttp.responseText);
    errorcallback(xmlHttp.responseText);
  }
  var method = "GET"
  if (params) method = "POST"
  xmlHttp.open(method, url, true);
  if (method = "POST")
    xmlHttp.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
  xmlHttp.send(params);
}
function postClick(e) {
  e = e || window.event;
  if (e.target.className.indexOf("expando-button") == -1) { return }
  var targ = e.currentTarget || e.srcElement || e;
  if (targ.nodeType == 3) targ = targ.parentNode;
  var bdy = targ.getElementsByClassName("expando")[0]
  var btn = targ.getElementsByClassName("expando-button")[0]
  if (bdy.className.indexOf("open")>-1) {
    bdy.className = 'expando';
    btn.className = "expando-button"
    targ.getElementsByClassName("embed")[0].innerHTML = ""
  } else {
    bdy.className = 'expando open';
    btn.className = "expando-button open"
    var url = targ.getElementsByClassName("url")[0].href
    if (id = parse_youtube(url)) {
      targ.getElementsByClassName("embed")[0].innerHTML = youtube_iframe(id)
    }
  }
}
function commentClick(e) {
  e = e || window.event;
  var targ = e.currentTarget || e.srcElement || e;
  if (targ.nodeType == 3) targ = targ.parentNode;
  if (e.target.name=="submit") {
    e.preventDefault()
    var form = e.target.parentNode
    if (form) {
      data = new FormData(form)
      if (("c"+data.get("commentid")) != targ.id) { return }
      params = new URLSearchParams(data).toString()
      params += "&" + e.target.name + "=" + e.target.value
      params += "&xhr=1"
      e.target.disabled = "disabled"
      request(targ.target || "", params,
        function(res){
          targ.outerHTML = res
        },
        function(res){
          e.target.disabled = ""
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
  if (e.target.className.indexOf("hidechildren") != -1) {
    if (e.target.getAttribute("for") != targ.id) { return }
    e.preventDefault()
    var btn = targ.getElementsByClassName("hidechildren")[0]
    var children = targ.getElementsByClassName("children")[0]
    if (children.className.indexOf("hidden") == -1) {
      children.className = "children hidden"
      btn.className = "hidechildren hidden"
    } else {
      children.className = "children"
      btn.className = "hidechildren"
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
function loadMore(e) {
  e.preventDefault()
  page = e.target.getAttribute("data-page")
  e.target.disabled="disabled"
  e.target.value="loading"
  var urlParams = new URLSearchParams(window.location.search);
  urlParams.set("xhr", "1")
  urlParams.set("page", page)
  request(window.location.origin+window.location.pathname+"?"+urlParams.toString(), "",
    function(res){
      if (res.trim()) {
        e.target.outerHTML = res + '<input id="loadmore" type="submit" data-page="'+(parseInt(page)+1)+'" value="load more" onclick="loadMore(event)">'
        if (showimages = document.getElementById("showimages")) {
          if (showimages.className == "selected") {
            toggle_images(true)
          }
        }
      }
      else {
        e.target.outerHTML = '<input id="end" type="submit" value="" disabled>'
      }
    },
    function(res) {
      e.target.outerHTML = '<input id="end" type="submit" value="loading failed" onclick="loadMore(event)">'
    }
  )
  return false;
}
function hideAllChildComments(e) {
  e.preventDefault()
  var comments = document.getElementsByClassName("comment")
  for (var i = 0; i < comments.length; i++) {
    var comment = comments[i]
    var btn = comment.getElementsByClassName("hidechildren")
    if (!btn.length) { continue }
    btn = btn[0]
    if (btn.getAttribute("for") != comment.id) { continue }
    var children = comment.getElementsByClassName("children")[0]
    if (children.className.indexOf("hidden") == -1) {
      children.className = "children hidden"
      btn.className = "hidechildren hidden"
      e.target.innerHTML = "show all child comments"
    } else {
      children.className = "children"
      btn.className = "hidechildren"
      e.target.innerHTML = "hide all child comments"
    }
  }
  return false
}
function formSubmit(e) {
  e = e || window.event;
  var targ = e.currentTarget || e.srcElement || e;
  e.preventDefault()
  var data = new FormData(targ)
  params = new URLSearchParams(data).toString()
  params += "&" + e.submitter.name + "=" + e.submitter.value
  params += "&xhr=1"
  e.submitter.disabled = "disabled"
  request(targ.target, params,
    function(res){
      targ.outerHTML = res
    },
    function(res){
      e.submitter.disabled = ""
    }
  )
  return false
}

function parse_youtube(url){
  if (url.indexOf("youtu") == -1) return false
  var regExp = /^.*(?:(?:youtu\.be\/|v\/|vi\/|u\/\w\/|embed\/|shorts\/)|(?:(?:watch)?\?v(?:i)?=|\&v(?:i)?=))([^#\&\?]*).*/;
  var match = url.match(regExp);
  if (match && match.length > 1) {
    return match[1]
  }
  return false
}
function youtube_iframe(id) {
  return '<iframe width="560" height="315" src="https://www.youtube.com/embed/'+id+'" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>'
}

function show_images(e) {
  e = e || window.event;
  e.preventDefault()
  var targ = e.currentTarget || e.srcElement || e;
  console.log(targ)
  var parent = targ.parentNode
  if (parent.className == "") {
    parent.className = "selected"
    toggle_images(true)
  } else {
    parent.className = ""
    toggle_images(false)
  }
  return false
}

function toggle_images(open) {
  var posts = document.getElementsByClassName("post")
  for (var i = 0; i < posts.length; i++) {
    var btn = posts[i].getElementsByClassName("expando-button")[0]
    if (btn.className.indexOf("hidden") != -1) { continue }
    var img = posts[i].getElementsByClassName("image")
    if (!img.length) { continue }
    var bdy = posts[i].getElementsByClassName("expando")[0]
    if (open) {
      bdy.className = 'expando open showimage';
      btn.className = "expando-button open"
    } else {
      bdy.className = 'expando';
      btn.className = "expando-button"
    }
  }
}

var posts = document.getElementsByClassName("post")
for (var i = 0; i < posts.length; i++) {
  var url = posts[i].getElementsByClassName("url")[0].href
  if (id = parse_youtube(url)) {
    var btn = posts[i].getElementsByClassName("expando-button")[0]
    if (btn.className.indexOf("open") > -1) {
      posts[i].getElementsByClassName("embed")[0].innerHTML = youtube_iframe(id)
    } else {
      btn.className = "expando-button"
    }
  }
}

window.onscroll = function(ev) {
    if ((window.innerHeight + window.pageYOffset) >= document.body.offsetHeight) {
      var loadmore = document.getElementById("loadmore")
      if (loadmore) {
        loadmore.click()
      }
    }
};

