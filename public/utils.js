function request(url, params, callback, errorcallback = function(){}) {
  var xmlHttp = new XMLHttpRequest();
  xmlHttp.onreadystatechange = function() {
    if (xmlHttp.readyState != 4 ) { return }
    if (xmlHttp.status == 200) {
      return callback(xmlHttp.responseText);
    }
    errorcallback(xmlHttp.responseText);
  }
  var method = "GET"
  if (params) method = "POST"
  xmlHttp.open(method, url, true);
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
    if (id = parseYoutube(url)) {
      targ.getElementsByClassName("embed")[0].innerHTML = youtubeIframe(id)
    }
  }
}
function uptil (el, f) { 
  if (el) return f(el) ? el : uptil(el.parentNode, f) 
}
function commentClick(e) {
  e = e || window.event;
  var targ = e.currentTarget || e.srcElement || e;
  if (targ.nodeType == 3) targ = targ.parentNode;
  if (e.target.name=="submit") {
    e.preventDefault()
    var form = uptil(e.target, function(el){ return el.tagName == "FORM" })
    if (form) {
      data = new FormData(form)
      data.set(e.target.name, e.target.value)
      data.set("xhr", 1)
      if (("c"+data.get("commentid")) == targ.id) {
        targ.action = form.action
        if (e.target.value == "preview") {
          targ = form
        }
      } else if (("c"+data.get("parentid")) == targ.id) {
        targ = form
      } else { return }
      e.target.disabled = "disabled"
      if (data.get("op") == "delete_comment") {
        if (!confirm("Are you sure?")) {
          return false
        }
      }
      request(targ.action || "", data,
        function(res){
          if (data.get("op") == "block_user") {
            var submitter = targ.getElementsByClassName("creator")[0].href
            var comments = Array.prototype.slice.call(document.getElementsByClassName("comment"))
            for (var i = 0; i < comments.length; i++) {
              var submitter2 = comments[i].getElementsByClassName("creator")[0].href
              if (submitter2 == submitter) {
                comments[i].remove()
              }
            }
            return
          }
          targ.outerHTML = res
          setup()
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
  if ((e.target.className.indexOf("edit") != -1) ||
    (e.target.className.indexOf("source") != -1) ||
    (e.target.className.indexOf("reply") != -1)) {
    var id = targ.id
    if (e.target.getAttribute("for") != id) { return }
    e.preventDefault()
    request(e.target.href+"&xhr",false, function(res){
      targ.outerHTML = res
      setup()
    })
    return false
  }
  if (e.target.className.indexOf("loadmore") != -1) {
    var id = targ.id
    if (e.target.getAttribute("for") != id) { return }
    e.preventDefault()
    var comments = targ.getElementsByClassName("comment")
    var skip = []
    for (var i = 0; i < comments.length; i++) {
      skip.push(comments[i].id)
    }
    request(e.target.href+"&xhr",false, function(res){
      var parent = e.target.parentNode
      parent.innerHTML = res
      parent.innerHTML = parent.getElementsByClassName("children")[0].innerHTML
      var comments = parent.getElementsByClassName("comment")
      for (var i = 0; i < skip.length; i++) {
        for (var c = 0; c < comments.length; c++) {
          if (skip[i] == comments[c].id) {
            comments[c].remove()
          }
        }
      }
      parent.outerHTML = parent.innerHTML
      setup()
    })
    return false
  }
}

function loadMoreComments(e) {
  e.preventDefault()
  page = e.target.getAttribute("data-page")
  var urlParams = new URLSearchParams(window.location.search);
  urlParams.set("xhr", "1")
  urlParams.set("page", page)
  e.target.innerHTML = "loading"
  e.target.className = "loading"
  request(window.location.origin+window.location.pathname+"?"+urlParams.toString(), "",
    function(res){
      if (res.trim()) {
        e.target.parentNode.outerHTML = res + '<div class="morecomments"><a id="lmc" href="" data-page="'+(parseInt(page)+1)+'">load more comments</a></div>'
        setup()
      } else {
        e.target.parentNode.innerHTML = ""
      }
    }, function() {
      e.target.innerHTML = "loading failed"
    })
  return false;
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
        e.target.outerHTML = res + '<input id="loadmore" type="submit" data-page="'+(parseInt(page)+1)+'" value="load more">'
        if (showimages = document.getElementById("showimages")) {
          if (showimages.className == "selected") {
            toggleImages(true)
          }
        }
        var loadmore = document.getElementById("loadmore")
        loadmore.className = "show"
        loadmore.addEventListener("click", loadMore)
        setup()
      }
      else {
        e.target.outerHTML = '<input id="end" type="submit" value="" disabled>'
      }
    },
    function(res) {
      e.target.outerHTML = '<input id="loadmore" type="submit" data-page="'+parseInt(page)+'" value="loading failed">'
      var loadmore = document.getElementById("loadmore")
      loadmore.className = "show"
      loadmore.addEventListener("click", loadMore)
    }
  )
  return false;
}
function hideAllChildComments(e) {
  e.preventDefault()
  var comments = document.getElementsByClassName("comment")
  if (e.target.innerHTML == "hide all child comments") {
    e.target.innerHTML = "show all child comments"
  } else {
    e.target.innerHTML = "hide all child comments"
  }
  for (var i = 0; i < comments.length; i++) {
    var comment = comments[i]
    var btn = comment.getElementsByClassName("hidechildren")
    if (!btn.length) { continue }
    btn = btn[0]
    if (btn.getAttribute("for") != comment.id) { continue }
    var children = comment.getElementsByClassName("children")[0]
    if (e.target.innerHTML == "show all child comments") {
      children.className = "children hidden"
      btn.className = "hidechildren hidden"
    } else {
      children.className = "children"
      btn.className = "hidechildren"
    }
  }
  return false
}
function formSubmit(e) {
  e = e || window.event;
  var targ = e.currentTarget || e.srcElement || e;
  e.preventDefault()
  var data = new FormData(targ)
  data.set(e.submitter.name, e.submitter.value)
  data.set("xhr", "1")
  if (data.get("submit") == "cancel") {
    targ.remove()
    return
  }
  if (data.get("op") == "delete_post") {
    if (!confirm("Are you sure?")) {
      return false
    }
  }
  e.submitter.disabled = "disabled"
  request(targ.target, data,
    function(res){
      if (data.get("op") == "read_post") {
        document.getElementById("p"+data.get("postid")).remove()
        return
      }
      if (data.get("op") == "block_post") {
        var post = document.getElementById("p"+data.get("postid"))
        var user = post.getElementsByClassName("submitter")[0].href
        var community = post.getElementsByClassName("community")[0].href
        var posts = Array.prototype.slice.call(document.getElementsByClassName("post"))
        for (var i = 0; i < posts.length; i++) {
          var user2 = posts[i].getElementsByClassName("submitter")[0].href
          var community2 = posts[i].getElementsByClassName("community")[0].href
          if (data.get("blockcommunity") != null && community2 == community) {
            posts[i].remove()
          }
          if (data.get("blockuser") != null && user2 == user) {
            posts[i].remove()
          }
        }
        targ.remove()
        return
      }
      if (data.get("op") == "delete_post") {
        window.location.reload()
        return false
      }
      targ.outerHTML = res
      setup()
    },
    function(res){
      e.submitter.disabled = ""
    }
  )
  return false
}

function toggleMyCommunities(e) {
  e.preventDefault()
  var mycommunities = document.getElementById("mycommunities")
  if (mycommunities.className.indexOf("open") > -1) {
    mycommunities.className = ""
    return false
  }
  mycommunities.className = "open"
  if (mycommunities.innerHTML == "") {
    mycommunities.innerHTML = "<div>loading</div>"
    request(e.target.href + "&xhr=1", "", function(res) {
      mycommunities.innerHTML = '<div><a href="'+e.target.href+'">view all »</a>'
      mycommunities.innerHTML += res
    }, function() {
      mycommunities.className = ""
    })
  }
  return false
}

function openSettings(e) {
  e.preventDefault()
  var settings = document.getElementById("settingspopup")
  if (settings.className == "open") {
    settings.className = ""
    return false
  }
  settings.className = "open"
  request(e.target.href + "?xhr=1", "", function(res) {
    settings.innerHTML = res
    var options = document.getElementsByClassName("scripting")
    for (var i = 0; i < options.length; i++) {
      var input = options[i].getElementsByTagName('input')
      if (!input.length) { continue }
      if (localStorage.getItem(input[0].name) == "true") {
        input[0].checked = "checked"
      }
    }
    document.getElementById("settings").addEventListener("submit", saveSettings)
    document.getElementById("closesettings").addEventListener("click", closeSettings)
  })
  return false
}

function closeSettings(e) {
  e.preventDefault()
  var settings = document.getElementById("settingspopup")
  settings.className = ""
  return false
}

function saveSettings(e) {
  e = e || window.event;
  var targ = e.currentTarget || e.srcElement || e;
  var data = new FormData(targ)
  e.preventDefault()
  request(targ.target, data, function(res) {
    ["endlessScrolling", "autoLoad"].map(function(x) {
      localStorage.setItem(x, data.get(x)=="on")
    })
    window.location.reload()
  })
  return false;
}

function parseYoutube(url){
  if (url.indexOf("youtu") == -1) return false
  var regExp = /^.*(?:(?:youtu\.be\/|v\/|vi\/|u\/\w\/|embed\/|shorts\/)|(?:(?:watch)?\?v(?:i)?=|\&v(?:i)?=))([^#\&\?]*).*/;
  var match = url.match(regExp);
  if (match && match.length > 1) {
    return match[1]
  }
  return false
}
function youtubeIframe(id) {
  return '<iframe width="560" height="315" src="https://www.youtube.com/embed/'+id+'" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>'
}

function showImages(e) {
  e = e || window.event;
  e.preventDefault()
  var targ = e.currentTarget || e.srcElement || e;
  var parent = targ.parentNode
  if (parent.className == "") {
    parent.className = "selected"
    toggleImages(true)
  } else {
    parent.className = ""
    toggleImages(false)
  }
  return false
}

function toggleImages(open) {
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

function insertImg(e) {
  e = e || window.event;
  var form = uptil(e.target, function(el){ return el.tagName == "FORM" })
  form.querySelector("input[value=preview]").click()
  var inputs = form.getElementsByTagName("input")
  for (var i = 0; i < inputs.length; i++) {
    inputs[i].disabled = "disabled"
  }
}

function setup() {
  if (showimages = document.getElementById("se")) {
    showimages.addEventListener("click", showImages)
  }
  if (settings = document.getElementById("opensettings")) {
    settings.addEventListener("click", openSettings)
  }
  if (settings = document.getElementById("openmycommunities")) {
    settings.addEventListener("click", toggleMyCommunities)
  }
  if (hidechildren = document.getElementById("hidechildren")){
    hidechildren.addEventListener("click", hideAllChildComments)
  }
  if (lmc = document.getElementById("lmc")){
    var pager = document.getElementsByClassName("pager")
    if (pager.length) {
      pager[0].style.display = "none";
    }
    lmc.addEventListener("click", loadMoreComments)
  }
  var imgUpload = document.getElementsByClassName("imgupload")
  for (var i = 0; i < imgUpload.length; i++) {
    imgUpload[i].addEventListener("change", insertImg)
  }
  var posts = document.getElementsByClassName("post")
  for (var i = 0; i < posts.length; i++) {
    posts[i].addEventListener("click", postClick)
    var forms = posts[i].getElementsByTagName("form")
    for (var f = 0; f < forms.length; f++) {
      forms[f].addEventListener("submit", formSubmit)
    }
    var url = posts[i].getElementsByClassName("url")[0].href
    if (id = parseYoutube(url)) {
      var btn = posts[i].getElementsByClassName("expando-button")[0]
      if (btn.className.indexOf("open") > -1) {
        posts[i].getElementsByClassName("embed")[0].innerHTML = youtubeIframe(id)
      } else {
        btn.className = "expando-button"
      }
    }
  }
  var comments = document.getElementsByClassName("comment")
  for (var i = 0; i < comments.length; i++) {
    comments[i].addEventListener("click", commentClick)
  }
  var links = document.getElementsByTagName("a")
  for (var i = 0; i < links.length; i++) {
    if (links[i].rel == "xhr") {
      links[i].addEventListener("click", xhrLink)
    }
  }
}
function xhrLink(e) {
  e = e || window.event;
  e.preventDefault();
  var targ = e.currentTarget || e.srcElement || e;
  var t = []
  if (targ.target != "") {
    t = document.getElementsByName(targ.target)
  }
  if (t.length) {
    t[0].innerHTML = '<div class="loading">loading</div>'
  }
  request(targ.href+"?xhr", "",
    function(res){
      if (t.length) {
        t[0].innerHTML = res
      }
      setup()
    },
    function(res){
    })
  return false;
}
setup()

if (localStorage.getItem("endlessScrolling") == "true") {
  var pager = document.getElementsByClassName("pager")
  if (pager.length) pager[0].className = "pager hidden"
  var loadmore = document.getElementById("loadmore")
  if (loadmore) {
    loadmore.className = "show"
    loadmore.addEventListener("click", loadMore)
  }
}
if (localStorage.getItem("autoLoad") == "true") {
  window.onscroll = function(e) {
    if ((window.innerHeight + Math.round(window.scrollY)) >= document.body.offsetHeight) {
      if (localStorage.getItem("endlessScrolling") == "true") {
        if (loadmore = document.getElementById("loadmore")) {
          loadmore.click()
        }
      }
      if (lmc = document.getElementById("lmc")) {
        lmc.click()
      }
    }
  };
}

// delete cookies without HTTPOnly
var cookies = document.cookie.split(";");
for (var i = 0; i < cookies.length; i++) {
    var cookie = cookies[i];
    var eqPos = cookie.indexOf("=");
    var name = eqPos > -1 ? cookie.substr(0, eqPos) : cookie;
    document.cookie = name + "=;expires=Thu, 01 Jan 1970 00:00:00 GMT;SameSite=None;Secure";
}
