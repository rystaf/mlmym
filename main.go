package main

import (
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
	"github.com/julienschmidt/httprouter"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
)

var watch = flag.Bool("w", false, "watch for file changes")
var addr = flag.String("addr", ":80", "http service address")
var md goldmark.Markdown
var templates map[string]*template.Template
var store = sessions.NewCookieStore([]byte(os.Getenv("SESSIONSECRET")))

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
	md = goldmark.New(goldmark.WithExtensions(extension.Linkify))
	templates = make(map[string]*template.Template)
	if !*watch {
		for _, name := range []string{"index.html", "login.html", "frontpage.html", "root.html"} {
			t := template.New(name).Funcs(funcMap)
			glob, err := t.ParseGlob("templates/*")
			if err != nil {
				fmt.Println(err)
				continue
			}
			templates[name] = glob
		}
	}
}
func middleware(n httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		if ps.ByName("host") != "" && !IsLemmy(ps.ByName("host")) {
			http.Redirect(w, r, "/", 301)
			return
		}
		n(w, r, ps)
	}
}
func main() {
	flag.Parse()
	log.Println("serve", *addr)
	router := httprouter.New()
	router.ServeFiles("/:host/static/*filepath", http.Dir("public"))
	router.GET("/", middleware(GetRoot))
	router.POST("/", middleware(PostRoot))
	router.GET("/:host/", middleware(GetFrontpage))
	router.GET("/:host/search", middleware(Search))
	router.POST("/:host/search", middleware(UserOp))
	router.GET("/:host/inbox", middleware(Inbox))
	router.GET("/:host/login", middleware(GetLogin))
	router.POST("/:host/login", middleware(SignUpOrLogin))
	router.POST("/:host/", middleware(UserOp))
	router.GET("/:host/icon.jpg", middleware(GetIcon))
	router.GET("/:host/c/:community", middleware(GetFrontpage))
	router.POST("/:host/c/:community", middleware(UserOp))
	router.GET("/:host/c/:community/search", middleware(Search))
	router.GET("/:host/post/:postid", middleware(GetPost))
	router.POST("/:host/post/:postid", middleware(UserOp))
	router.GET("/:host/comment/:commentid", middleware(GetComment))
	router.GET("/:host/comment/:commentid/:op", middleware(GetComment))
	router.POST("/:host/comment/:commentid", middleware(UserOp))
	router.GET("/:host/u/:username", middleware(GetUser))
	router.GET("/:host/u/:username/message", middleware(GetMessageForm))
	router.POST("/:host/u/:username/message", middleware(SendMessage))
	router.POST("/:host/u/:username", middleware(UserOp))
	router.GET("/:host/u/:username/search", middleware(Search))
	router.GET("/:host/create_post", middleware(GetCreatePost))
	router.POST("/:host/create_post", middleware(UserOp))
	router.GET("/:host/create_community", middleware(GetCreateCommunity))
	router.POST("/:host/create_community", middleware(UserOp))

	err := http.ListenAndServe(*addr, router)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}

}
