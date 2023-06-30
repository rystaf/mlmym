package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/dustin/go-humanize"
	"github.com/julienschmidt/httprouter"
	"github.com/rystaf/go-lemmy"
	"github.com/rystaf/go-lemmy/types"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

var funcMap = template.FuncMap{
	"proxy": func(s string) string {
		u, err := url.Parse(s)
		if err != nil {
			return s
		}
		return "/" + u.Host + u.Path
	},
	"printer": func(n any) string {
		p := message.NewPrinter(language.English)
		return p.Sprintf("%d", n)
	},
	"likedPerc": func(c types.PostAggregates) string {
		return fmt.Sprintf("%.1f", (float64(c.Upvotes)/float64(c.Upvotes+c.Downvotes))*100)
	},
	"fullname": func(person types.PersonSafe) string {
		if person.Local {
			return person.Name
		}
		l, err := url.Parse(person.ActorID)
		if err != nil {
			fmt.Println(err)
			return person.Name
		}
		return person.Name + "@" + l.Host
	},
	"fullcname": func(c types.CommunitySafe) string {
		if c.Local {
			return c.Name
		}
		l, err := url.Parse(c.ActorID)
		if err != nil {
			fmt.Println(err)
			return c.Name
		}
		return c.Name + "@" + l.Host
	},
	"isMod": func(c *types.GetCommunityResponse, username string) bool {
		for _, mod := range c.Moderators {
			if mod.Moderator.Local && username == mod.Moderator.Name {
				return true
			}
		}
		return false
	},
	"host": func(p Post) string {
		if p.Post.URL.IsValid() {
			l, err := url.Parse(p.Post.URL.String())
			if err != nil {
				return ""
			}
			return l.Host
		}
		if p.Post.Local {
			return "self." + p.Community.Name
		}
		l, err := url.Parse(p.Post.ApID)
		if err != nil {
			return ""
		}
		return l.Host
	},
	"membership": func(s types.SubscribedType) string {
		switch s {
		case types.SubscribedTypeSubscribed:
			return "leave"
		case types.SubscribedTypeNotSubscribed:
			return "join"
		case types.SubscribedTypePending:
			return "pending"
		}
		return ""
	},
	"isImage": func(url string) bool {
		ext := url[len(url)-4:]
		if ext == "jpeg" || ext == ".jpg" || ext == ".png" || ext == "webp" || ext == ".gif" {
			return true
		}
		return false
	},
	"humanize": humanize.Time,
	"markdown": func(host string, body string) template.HTML {
		var buf bytes.Buffer
		if err := md.Convert([]byte(body), &buf); err != nil {
			panic(err)
		}
		converted := strings.Replace(buf.String(), `href="https://`+host, `href="/`+host, -1)
		return template.HTML(converted)
	},
	"contains": strings.Contains,
	"sub": func(a int, b int) int {
		return int(a) - b
	},
}

func Initialize(Host string, r *http.Request) (State, error) {
	state := State{
		Host:   Host,
		Sort:   "Hot",
		Page:   1,
		Status: http.StatusOK,
	}
	state.ParseQuery(r.URL.RawQuery)
	client := http.Client{Transport: NewAddHeaderTransport(r.RemoteAddr)}
	c, err := lemmy.NewWithClient("https://"+state.Host, &client)
	if err != nil {
		fmt.Println(err)
		state.Status = http.StatusInternalServerError
		return state, err
	}
	state.HTTPClient = &client
	state.Client = c
	session, err := store.Get(r, state.Host)
	if err == nil {
		token, ok1 := session.Values["token"].(string)
		username, ok2 := session.Values["username"].(string)
		userid, ok3 := session.Values["id"].(int)
		if ok1 && ok2 && ok3 {
			state.Client.Token = token
			sess := Session{
				UserName: username,
				UserID:   userid,
			}
			state.Session = &sess
			if state.Listing == "" {
				state.Listing = "Subscribed"
			}
		}
	}
	if state.Listing == "" {
		state.Listing = "All"
	}
	return state, nil
}
func GetTemplate(name string) (*template.Template, error) {
	if *watch {
		t := template.New(name).Funcs(funcMap)
		glob, err := t.ParseGlob("templates/*")
		if err != nil {
			return nil, err
		}
		return glob, nil
	}
	t, ok := templates[name]
	if !ok {
		return nil, errors.New("template not found")
	}
	return t, nil
}
func Render(w http.ResponseWriter, templateName string, state State) {
	tmpl, err := GetTemplate(templateName)
	if err != nil {
		w.Write([]byte("500 - Server Error"))
		return
	}
	if len(state.TopCommunities) == 0 {
		state.GetCommunities()
	}
	if state.Session != nil {
		state.GetUnreadCount()
	}
	if state.Status != http.StatusOK {
		w.WriteHeader(state.Status)
	}
	err = tmpl.Execute(w, state)
	if err != nil {
		fmt.Println("execute fail", err)
		w.Write([]byte("500 - Server Error"))
		return
	}
}
func GetRoot(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	data := make(map[string]any)
	tmpl, err := GetTemplate("root.html")
	if err != nil {
		fmt.Println("execute fail", err)
		w.Write([]byte("500 - Server Error"))
		return
	}
	tmpl.Execute(w, data)
}

type NodeSoftware struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
type NodeInfo struct {
	Software NodeSoftware `json:"software"`
}

func IsLemmy(domain string) bool {
	var nodeInfo NodeInfo
	res, err := http.Get("https://" + domain + "/nodeinfo/2.0.json")
	if err != nil {
		return false
	}
	err = json.NewDecoder(res.Body).Decode(&nodeInfo)
	if err != nil {
		return false
	}
	if nodeInfo.Software.Name == "lemmy" {
		return true
	}
	return false
}

func PostRoot(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	data := make(map[string]any)
	tmpl, err := GetTemplate("root.html")
	if err != nil {
		fmt.Println("execute fail", err)
		w.Write([]byte("500 - Server Error"))
		return
	}

	var dest url.URL
	re := regexp.MustCompile(`^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z
 ]{2,3})$`)
	if re.MatchString(r.FormValue("destination")) {
		dest.Host = r.FormValue("destination")
	} else if u, err := url.Parse(r.FormValue("destination")); err == nil && u.Host != "" {
		dest.Parse(u.String())
	}
	if dest.Host != "" && IsLemmy(dest.Host) {
		redirectUrl := "/" + dest.Host + dest.Path
		if dest.RawQuery != "" {
			redirectUrl = redirectUrl + "?" + dest.RawQuery
		}
		http.Redirect(w, r, redirectUrl, 301)
		return
	}
	data["Error"] = "Invalid destination"
	tmpl.Execute(w, data)
}
func GetIcon(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	if ps.ByName("host") == "favicon.ico" {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("404 - Not Found"))
	}
	state, err := Initialize(ps.ByName("host"), r)
	state.Client.Token = ""
	resp, err := state.Client.Site(context.Background(), types.GetSite{})
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("500 - Server Error"))
		return
	}
	if !resp.SiteView.Site.Icon.IsValid() {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("404 - Not Found"))
		return
	}
	iresp, err := state.HTTPClient.Get(resp.SiteView.Site.Icon.String())
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("500 - Server Error"))
		return
	}
	defer iresp.Body.Close()
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "max-age=2592000")
	io.Copy(w, iresp.Body)
	return

}
func GetFrontpage(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	state, err := Initialize(ps.ByName("host"), r)
	if err != nil {
		Render(w, "index.html", state)
		return
	}
	m, _ := url.ParseQuery(r.URL.RawQuery)
	if len(m["edit"]) > 0 {
		state.Op = "edit_community"
	}
	if ps.ByName("community") == "" || state.Op == "edit_community" {
		state.GetSite()
	}
	state.GetCommunity(ps.ByName("community"))
	if state.Op == "" {
		state.GetPosts()
	}
	Render(w, "frontpage.html", state)
}

func GetPost(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	state, err := Initialize(ps.ByName("host"), r)
	if err != nil {
		Render(w, "index.html", state)
		return
	}
	m, _ := url.ParseQuery(r.URL.RawQuery)
	if len(m["edit"]) > 0 {
		state.Op = "edit_post"
		state.GetSite()
	}
	postid, _ := strconv.Atoi(ps.ByName("postid"))
	state.GetPost(postid)
	state.GetComments()
	Render(w, "index.html", state)
}
func GetComment(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	state, err := Initialize(ps.ByName("host"), r)
	if err != nil {
		Render(w, "index.html", state)
		return
	}
	m, _ := url.ParseQuery(r.URL.RawQuery)
	if len(m["reply"]) > 0 {
		state.Op = "reply"
	}
	if len(m["edit"]) > 0 {
		state.Op = "edit"
	}
	if len(m["source"]) > 0 {
		state.Op = "source"
	}
	commentid, _ := strconv.Atoi(ps.ByName("commentid"))
	state.GetComment(commentid)
	state.GetPost(state.PostID)
	Render(w, "index.html", state)
}
func GetUser(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	state, err := Initialize(ps.ByName("host"), r)
	if err != nil {
		Render(w, "index.html", state)
		return
	}
	state.GetUser(ps.ByName("username"))
	Render(w, "index.html", state)
}
func GetMessageForm(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	state, err := Initialize(ps.ByName("host"), r)
	if err != nil {
		Render(w, "index.html", state)
		return
	}
	state.Op = "send_message"
	state.GetUser(ps.ByName("username"))
	Render(w, "index.html", state)
}
func SendMessage(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	state, err := Initialize(ps.ByName("host"), r)
	if err != nil {
		Render(w, "index.html", state)
		return
	}
	userid, _ := strconv.Atoi(r.FormValue("userid"))
	_, err = state.Client.CreatePrivateMessage(context.Background(), types.CreatePrivateMessage{
		Content:     r.FormValue("content"),
		RecipientID: userid,
	})
	if err != nil {
		state.Error = err
		Render(w, "index.html", state)
		return
	}
	r.URL.Path = "/" + state.Host + "/inbox"
	http.Redirect(w, r, r.URL.String(), 301)
}
func GetCreatePost(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	state, err := Initialize(ps.ByName("host"), r)
	if err != nil {
		Render(w, "index.html", state)
		return
	}
	state.GetSite()
	state.GetCommunity("")
	state.Op = "create_post"
	Render(w, "index.html", state)
}
func GetCreateCommunity(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	state, err := Initialize(ps.ByName("host"), r)
	if err != nil {
		Render(w, "index.html", state)
		return
	}
	state.GetSite()
	state.Op = "create_community"
	Render(w, "index.html", state)
}

func Inbox(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	state, err := Initialize(ps.ByName("host"), r)
	if err != nil {
		Render(w, "index.html", state)
		return
	}
	state.GetMessages()
	Render(w, "index.html", state)
	state.MarkAllAsRead()
}

func SignUpOrLogin(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	state, err := Initialize(ps.ByName("host"), r)
	if err != nil {
		Render(w, "index.html", state)
		return
	}
	var token string
	switch r.FormValue("submit") {
	case "log in":
		resp, err := state.Client.Login(context.Background(), types.Login{
			UsernameOrEmail: r.FormValue("username"),
			Password:        r.FormValue("password"),
		})
		if err != nil {
			state.Error = err
			state.GetSite()
			state.GetCaptcha()
			Render(w, "login.html", state)
			return
		}
		if resp.JWT.IsValid() {
			token = resp.JWT.String()
		}
	case "sign up":
		register := types.Register{
			Username:       r.FormValue("username"),
			Password:       r.FormValue("password"),
			PasswordVerify: r.FormValue("passwordverify"),
			ShowNSFW:       r.FormValue("nsfw") != "",
		}
		if r.FormValue("email") != "" {
			register.Email = types.NewOptional(r.FormValue("email"))
		}
		if r.FormValue("answer") != "" {
			register.Answer = types.NewOptional(r.FormValue("answer"))
		}
		if r.FormValue("captchauuid") != "" {
			register.CaptchaUuid = types.NewOptional(r.FormValue("captchauuid"))
		}
		if r.FormValue("captchaanswer") != "" {
			register.CaptchaAnswer = types.NewOptional(r.FormValue("captchaanswer"))
		}
		resp, err := state.Client.Register(context.Background(), register)
		if err != nil {
			state.Error = err
			state.GetSite()
			state.GetCaptcha()
			Render(w, "login.html", state)
			return
		}
		if resp.JWT.IsValid() {
			token = resp.JWT.String()
		} else {
			var alert string
			if resp.RegistrationCreated {
				alert = "Registration application submitted. "
			}
			if resp.VerifyEmailSent {
				alert = alert + "Email verification sent. "
			}
			q := r.URL.Query()
			q.Add("alert", alert)
			r.URL.RawQuery = q.Encode()
			http.Redirect(w, r, r.URL.String(), 301)
		}
	}
	if token != "" {
		session, err := store.Get(r, state.Host)
		if err != nil {
			state.Error = err
			state.GetSite()
			state.GetCaptcha()
			Render(w, "login.html", state)
			return
		}
		if resp, err := state.Client.Site(context.Background(), types.GetSite{
			Auth: types.NewOptional(token),
		}); err != nil {
			fmt.Println(err)
			return
		} else if myUser, err := resp.MyUser.Value(); err == nil {
			// Error is nil when value is nil?
			return
		} else {
			session.Values["username"] = myUser.LocalUserView.Person.Name
			session.Values["id"] = myUser.LocalUserView.Person.ID
		}
		session.Values["token"] = token
		session.Save(r, w)
		r.URL.Path = "/" + state.Host
		http.Redirect(w, r, r.URL.String(), 301)
		return
	}
}
func GetLogin(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	state, err := Initialize(ps.ByName("host"), r)
	if err != nil {
		Render(w, "index.html", state)
		return
	}
	state.GetSite()
	state.GetCaptcha()
	m, _ := url.ParseQuery(r.URL.RawQuery)
	if len(m["alert"]) > 0 {
		state.Alert = m["alert"][0]
	}
	Render(w, "login.html", state)
}
func Search(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	state, err := Initialize(ps.ByName("host"), r)
	if err != nil {
		Render(w, "index.html", state)
		return
	}
	if state.CommunityName != "" {
		state.GetCommunity(ps.ByName("community"))
	}
	if state.UserName != "" {
		state.GetUser(state.UserName)
	} else if state.Community == nil {
		state.GetSite()
	}
	m, _ := url.ParseQuery(r.URL.RawQuery)
	state.SearchType = "Posts"
	if len(m["searchtype"]) > 0 {
		switch m["searchtype"][0] {
		case "Comments":
			state.SearchType = "Comments"
		case "Communities":
			state.SearchType = "Communities"
			state.Listing = "All"
		}
	}
	state.Search(state.SearchType)
	Render(w, "index.html", state)
}

type PictrsFile struct {
	Filename    string `json:"file"`
	DeleteToken string `json:"delete_token"`
}

type PictrsResponse struct {
	Message string       `json:"msg"`
	Files   []PictrsFile `json:"files"`
}

func UserOp(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	state, err := Initialize(ps.ByName("host"), r)
	if err != nil {
		Render(w, "index.html", state)
		return
	}
	fmt.Println("user op ", r.FormValue("op"))
	switch r.FormValue("op") {
	case "leave":
		communityid, _ := strconv.Atoi(r.FormValue("communityid"))
		state.Client.FollowCommunity(context.Background(), types.FollowCommunity{
			CommunityID: communityid,
			Follow:      false,
		})
	case "join":
		communityid, _ := strconv.Atoi(r.FormValue("communityid"))
		state.Client.FollowCommunity(context.Background(), types.FollowCommunity{
			CommunityID: communityid,
			Follow:      true,
		})
	case "logout":
		if session, err := store.Get(r, state.Host); err == nil {
			session.Options.MaxAge = -1
			session.Save(r, w)
		}
	case "login":
		resp, err := state.Client.Login(context.Background(), types.Login{
			UsernameOrEmail: r.FormValue("user"),
			Password:        r.FormValue("pass"),
		})
		if err != nil {
			state.Status = http.StatusUnauthorized
		}
		if resp.JWT.IsValid() {
			session, err := store.Get(r, state.Host)
			if err == nil {
				state.GetUser(r.FormValue("user"))
				session.Values["token"] = resp.JWT.String()
				session.Values["username"] = state.User.PersonView.Person.Name
				session.Values["id"] = state.User.PersonView.Person.ID
				session.Save(r, w)
			}
		}
	case "create_community":
		state.GetSite()
		community := types.CreateCommunity{
			Name:  r.FormValue("name"),
			Title: r.FormValue("title"),
		}
		if r.FormValue("description") != "" {
			community.Description = types.NewOptional(r.FormValue("description"))
		}
		if file, handler, err := r.FormFile("icon"); err == nil {
			pres, err := state.UploadImage(file, handler)
			if err != nil {
				state.Error = err
				Render(w, "index.html", state)
				return
			}
			community.Icon = types.NewOptional("https://" + state.Host + "/pictrs/image/" + pres.Files[0].Filename)
		}
		if file, handler, err := r.FormFile("banner"); err == nil {
			pres, err := state.UploadImage(file, handler)
			if err != nil {
				state.Error = err
				Render(w, "index.html", state)
				return
			}
			community.Banner = types.NewOptional("https://" + state.Host + "/pictrs/image/" + pres.Files[0].Filename)
		}
		resp, err := state.Client.CreateCommunity(context.Background(), community)
		if err == nil {
			r.URL.Path = "/" + state.Host + "/c/" + resp.CommunityView.Community.Name
		} else {
			fmt.Println(err)
		}
	case "edit_community":
		state.CommunityName = ps.ByName("community")
		state.GetCommunity("")
		if state.Community == nil {
			Render(w, "index.html", state)
			return
		}
		state.GetSite()
		community := types.EditCommunity{
			CommunityID: state.Community.CommunityView.Community.ID,
		}
		if r.FormValue("title") != "" {
			community.Title = types.NewOptional(r.FormValue("title"))
		}
		if r.FormValue("description") != "" {
			community.Description = types.NewOptional(r.FormValue("description"))
		}
		if file, handler, err := r.FormFile("icon"); err == nil {
			pres, err := state.UploadImage(file, handler)
			if err != nil {
				state.Error = err
				Render(w, "index.html", state)
				return
			}
			community.Icon = types.NewOptional("https://" + state.Host + "/pictrs/image/" + pres.Files[0].Filename)
		}
		if file, handler, err := r.FormFile("banner"); err == nil {
			pres, err := state.UploadImage(file, handler)
			if err != nil {
				state.Error = err
				Render(w, "index.html", state)
				return
			}
			community.Banner = types.NewOptional("https://" + state.Host + "/pictrs/image/" + pres.Files[0].Filename)
		}
		resp, err := state.Client.EditCommunity(context.Background(), community)
		if err == nil {
			r.URL.Path = "/" + state.Host + "/c/" + resp.CommunityView.Community.Name
		} else {
			fmt.Println(err)
		}
	case "create_post":
		state.CommunityName = r.FormValue("communityname")
		state.GetCommunity("")
		state.GetSite()
		if state.Community == nil {
			state.Status = http.StatusBadRequest
			state.Op = "create_post"
			Render(w, "index.html", state)
			return
		}
		post := types.CreatePost{
			Name:        r.FormValue("name"),
			CommunityID: state.Community.CommunityView.Community.ID,
		}
		if r.FormValue("url") != "" {
			post.URL = types.NewOptional(r.FormValue("url"))
		}
		file, handler, err := r.FormFile("file")
		if err == nil {
			pres, err := state.UploadImage(file, handler)
			if err != nil {
				state.Error = err
				Render(w, "index.html", state)
				return
			}
			post.URL = types.NewOptional("https://" + state.Host + "/pictrs/image/" + pres.Files[0].Filename)
		}
		if r.FormValue("body") != "" {
			post.Body = types.NewOptional(r.FormValue("body"))
		}
		if r.FormValue("language") != "" {
			languageid, _ := strconv.Atoi(r.FormValue("language"))
			post.LanguageID = types.NewOptional(languageid)
		}
		resp, err := state.Client.CreatePost(context.Background(), post)
		if err == nil {
			postid := strconv.Itoa(resp.PostView.Post.ID)
			r.URL.Path = "/" + state.Host + "/post/" + postid
		} else {
			fmt.Println(err)
		}
	case "edit_post":
		r.ParseMultipartForm(10 << 20)
		state.GetSite()
		postid, _ := strconv.Atoi(ps.ByName("postid"))
		post := types.EditPost{
			PostID: postid,
			Body:   types.NewOptional(r.FormValue("body")),
			URL:    types.NewOptional(r.FormValue("url")),
		}
		if r.FormValue("url") == "" {
			post.URL = types.Optional[string]{}
		}
		if r.FormValue("language") != "" {
			languageid, _ := strconv.Atoi(r.FormValue("language"))
			post.LanguageID = types.NewOptional(languageid)
		}
		file, handler, err := r.FormFile("file")
		if err == nil {
			pres, err := state.UploadImage(file, handler)
			if err != nil {
				state.Error = err
				Render(w, "index.html", state)
				return
			}
			post.URL = types.NewOptional("https://" + state.Host + "/pictrs/image/" + pres.Files[0].Filename)
		}

		resp, err := state.Client.EditPost(context.Background(), post)
		if err == nil {
			postid := strconv.Itoa(resp.PostView.Post.ID)
			r.URL.Path = "/" + state.Host + "/post/" + postid
			r.URL.RawQuery = ""
		} else {
			state.Status = http.StatusBadRequest
			state.Error = err
			fmt.Println(err)
		}
	case "delete_post":
		postid, _ := strconv.Atoi(r.FormValue("postid"))
		fmt.Println("delete " + r.FormValue("postid"))
		post := types.DeletePost{
			PostID:  postid,
			Deleted: true,
		}
		if r.FormValue("undo") != "" {
			post.Deleted = false
		}
		resp, err := state.Client.DeletePost(context.Background(), post)
		if err != nil {
			fmt.Println(err)
		} else {
			r.URL.Path = "/" + state.Host + "/c/" + resp.PostView.Community.Name
			r.URL.RawQuery = ""
		}
	case "vote_post":
		var score int16
		score = 1
		if r.FormValue("vote") != "▲" {
			score = -1
		}
		if r.FormValue("undo") == strconv.Itoa(int(score)) {
			score = 0
		}
		postid, _ := strconv.Atoi(r.FormValue("postid"))
		post := types.CreatePostLike{
			PostID: postid,
			Score:  score,
		}
		state.Client.CreatePostLike(context.Background(), post)
	case "vote_comment":
		var score int16
		score = 1
		if r.FormValue("vote") != "▲" {
			score = -1
		}
		if r.FormValue("undo") == strconv.Itoa(int(score)) {
			score = 0
		}
		commentid, _ := strconv.Atoi(r.FormValue("commentid"))
		post := types.CreateCommentLike{
			CommentID: commentid,
			Score:     score,
		}
		state.Client.CreateCommentLike(context.Background(), post)
	case "create_comment":
		if ps.ByName("postid") != "" {
			postid, _ := strconv.Atoi(ps.ByName("postid"))
			state.PostID = postid
		}
		if r.FormValue("parentid") != "" {
			parentid, _ := strconv.Atoi(r.FormValue("parentid"))
			state.GetComment(parentid)
		}
		createComment := types.CreateComment{
			Content: r.FormValue("content"),
			PostID:  state.PostID,
		}
		if state.CommentID > 0 {
			createComment.ParentID = types.NewOptional(state.CommentID)
		}
		resp, err := state.Client.CreateComment(context.Background(), createComment)
		if err == nil {
			postid := strconv.Itoa(state.PostID)
			commentid := strconv.Itoa(resp.CommentView.Comment.ID)
			r.URL.Path = "/" + state.Host + "/post/" + postid
			r.URL.Fragment = "c" + commentid
		} else {
			fmt.Println(err)
		}
	case "edit_comment":
		commentid, _ := strconv.Atoi(r.FormValue("commentid"))
		resp, err := state.Client.EditComment(context.Background(), types.EditComment{
			CommentID: commentid,
			Content:   types.NewOptional(r.FormValue("content")),
		})
		if err != nil {
			fmt.Println(err)
		} else {
			commentid := strconv.Itoa(resp.CommentView.Comment.ID)
			r.URL.Fragment = "c" + commentid
			r.URL.RawQuery = ""
		}
	case "delete_comment":
		commentid, _ := strconv.Atoi(r.FormValue("commentid"))
		resp, err := state.Client.DeleteComment(context.Background(), types.DeleteComment{
			CommentID: commentid,
			Deleted:   true,
		})
		if err != nil {
			fmt.Println(err)
		} else {
			commentid := strconv.Itoa(resp.CommentView.Comment.ID)
			r.URL.Fragment = "c" + commentid
			r.URL.RawQuery = ""
		}
	}
	http.Redirect(w, r, r.URL.String(), 301)
}
