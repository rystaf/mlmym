package main

import (
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/julienschmidt/httprouter"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
)

var version string
var watch = flag.Bool("w", false, "watch for file changes")
var addr = flag.String("addr", ":80", "http service address")
var md goldmark.Markdown
var templates map[string]*template.Template

type AddHeaderTransport struct {
	T          http.RoundTripper
	ForwardFor string
}

func (adt *AddHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("User-Agent", "Mlmym")
	if adt.ForwardFor != "" {
		req.Header.Add("X-Forwarded-For", adt.ForwardFor)
		req.Header.Add("X-Real-IP", adt.ForwardFor)
	}
	return adt.T.RoundTrip(req)
}

func NewAddHeaderTransport(remoteAddr string) *AddHeaderTransport {
	var forwardFor string
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			if !ip.IsPrivate() {
				forwardFor = ip.String()
			}
		}
	}
	return &AddHeaderTransport{
		T:          http.DefaultTransport,
		ForwardFor: forwardFor,
	}
}

func init() {
	md = goldmark.New(goldmark.WithExtensions(
		extension.Linkify,
		extension.Table,
	))
	templates = make(map[string]*template.Template)
	if !*watch {
		for _, name := range []string{"index.html", "login.html", "frontpage.html", "root.html", "settings.html", "xhr.html", "create_comment.html", "block.html"} {
			t := template.New(name).Funcs(funcMap)
			glob, err := t.ParseGlob("templates/*")
			if err != nil {
				fmt.Println(err)
				continue
			}
			templates[name] = glob
		}
	}
	if os.Getenv("DEBUG") != "" {
		test()
	}
	if data, err := os.ReadFile("VERSION"); err == nil {
		version = string(data)
	}
}
func test() {
	links := [][]string{
		[]string{"https://lemmy.local/u/dude", "/lemmy.local/u/dude", "/u/dude"},
		[]string{"https://lemmy.local/u/dude@lemmy.local", "/lemmy.local/u/dude", "/u/dude"},
		[]string{"/u/dude", "/lemmy.local/u/dude", "/u/dude"},
		[]string{"/u/dude@lemmy.world", "/lemmy.local/u/dude@lemmy.world", "/u/dude@lemmy.world"},
		[]string{"/u/dude@lemmy.local", "/lemmy.local/u/dude", "/u/dude"},
		[]string{"https://lemmy.world/c/dude", "/lemmy.local/c/dude@lemmy.world", "/c/dude@lemmy.world"},
		[]string{"https://lemmy.world/u/dude", "/lemmy.local/u/dude@lemmy.world", "/u/dude@lemmy.world"},
		[]string{"https://lemmy.world/u/dude@lemmy.world", "/lemmy.local/u/dude@lemmy.world", "/u/dude@lemmy.world"},
		[]string{"https://lemmy.world/post/123", "/lemmy.local/post/123@lemmy.world", "/post/123@lemmy.world"},
		[]string{"https://lemmy.world/post/123#123", "https://lemmy.world/post/123#123", "https://lemmy.world/post/123#123"},
		[]string{"/post/123", "/lemmy.local/post/123", "/post/123"},
		[]string{"/comment/123", "/lemmy.local/comment/123", "/comment/123"},
		[]string{"https://lemmy.local/comment/123", "/lemmy.local/comment/123", "/comment/123"},
	}
	for _, url := range links {
		output := LemmyLinkRewrite(`href="`+url[0]+`"`, "lemmy.local", "")
		success := (output == (`href="` + url[1] + `"`))
		if !success {
			fmt.Println("\n!!!! multi instance link rewrite failure !!!!")
			fmt.Println(url)
			fmt.Println(output)
			fmt.Println("")
		}
		output = LemmyLinkRewrite(`href="`+url[0]+`"`, ".", "lemmy.local")
		success = (output == (`href="` + url[2] + `"`))
		if !success {
			fmt.Println("\n!!!! single instance link rewrite failure !!!!")
			fmt.Println(success, url)
			fmt.Println(output)
			fmt.Println("")
		}
	}
}
func RemoteAddr(r *http.Request) string {
	if r.Header.Get("CF-Connecting-IP") != "" {
		return r.Header.Get("CF-Connecting-IP")
	}
	return r.RemoteAddr
}
func middleware(n httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		//remoteAddr := r.RemoteAddr
		//if r.Header.Get("CF-Connecting-IP") != "" {
		//	remoteAddr = r.Header.Get("CF-Connecting-IP")
		//}
		//if ps.ByName("host") != "" && !IsLemmy(ps.ByName("host"), remoteAddr) {
		//	http.Redirect(w, r, "/", 301)
		//	return
		//}
		n(w, r, ps)
	}
}
func main() {
	flag.Parse()
	log.Println("serve", *addr)
	router := GetRouter()
	err := http.ListenAndServe(*addr, router)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}

}
