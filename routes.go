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
	"os"
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
	"host": func(host string) string {
		if l := os.Getenv("LEMMY_DOMAIN"); l != "" {
			return l
		}
		return host
	},
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
	"domain": func(p Post) string {
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
		converted := buf.String()
		converted = strings.Replace(converted, `<img `, `<img loading="lazy" `, -1)
		if os.Getenv("LEMMY_DOMAIN") == "" {
			re := regexp.MustCompile(`href="https:\/\/([a-zA-Z0-9\.\-]+\/(c\/[a-zA-Z0-9]+|(post|comment)\/\d+))`)
			converted = re.ReplaceAllString(converted, `href="/$1`)
		}
		re := regexp.MustCompile(`href="\/(c\/[a-zA-Z0-9\-]+|(post|comment)\/\d+)`)
		converted = re.ReplaceAllString(converted, `href="/`+host+`/$1`)
		re = regexp.MustCompile(` !([a-zA-Z0-9]+)@([a-zA-Z0-9\.\-]+) `)
		converted = re.ReplaceAllString(converted, ` <a href="/$2/c/$1">!$1@$2</a> `)
		return template.HTML(converted)
	},
	"contains": strings.Contains,
	"sub": func(a int32, b int) int {
		return int(a) - b
	},
}

func Initialize(Host string, r *http.Request) (State, error) {
	state := State{
		Host:   Host,
		Page:   1,
		Status: http.StatusOK,
	}
	lemmyDomain := os.Getenv("LEMMY_DOMAIN")
	if lemmyDomain != "" {
		state.Host = "."
		Host = lemmyDomain
	}
	remoteAddr := r.RemoteAddr
	if r.Header.Get("CF-Connecting-IP") != "" {
		remoteAddr = r.Header.Get("CF-Connecting-IP")
	}
	client := http.Client{Transport: NewAddHeaderTransport(remoteAddr)}
	c, err := lemmy.NewWithClient("https://"+Host, &client)
	if err != nil {
		fmt.Println(err)
		state.Status = http.StatusInternalServerError
		return state, err
	}
	state.HTTPClient = &client
	state.Client = c
	token := getCookie(r, "jwt")
	user := getCookie(r, "user")
	parts := strings.Split(user, ":")
	if len(parts) == 2 {
		if id, err := strconv.Atoi(parts[1]); err == nil {
			state.Client.Token = token
			sess := Session{
				UserName: parts[0],
				UserID:   id,
			}
			state.Session = &sess
		}
	}
	state.Listing = getCookie(r, "DefaultListingType")
	state.Sort = getCookie(r, "DefaultSortType")
	state.Dark = getCookie(r, "Dark") != ""
	state.ShowNSFW = getCookie(r, "ShowNSFW") != ""
	state.ParseQuery(r.URL.RawQuery)
	if state.Sort == "" {
		state.Sort = "Hot"
	}
	if state.Listing == "" || state.Session == nil && state.Listing == "Subscribed" {
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
		fmt.Println(err)
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

func IsLemmy(domain string, remoteAddr string) bool {
	client := http.Client{Transport: NewAddHeaderTransport(remoteAddr)}
	var nodeInfo NodeInfo
	res, err := client.Get("https://" + domain + "/nodeinfo/2.0.json")
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
	input := r.FormValue("destination")
	re := regexp.MustCompile(`^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z
 ]{2,3})`)
	if re.MatchString(input) {
		input = "https://" + input
	}
	dest, err := url.Parse(input)
	if dest.Host != "" {
		state, _ := Initialize(dest.Host, r)
		if err := state.LemmyError(dest.Host); err != nil {
			data["Error"] = err
		} else {
			redirectUrl := "/" + dest.Host + dest.Path
			if dest.RawQuery != "" {
				redirectUrl = redirectUrl + "?" + dest.RawQuery
			}
			http.Redirect(w, r, redirectUrl, 302)
			return
		}
	} else {
		data["Error"] = "Invalid destination"
	}
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
		fmt.Println(err)
		Render(w, "index.html", state)
		return
	}
	state.GetSite()
	state.Op = "create_community"
	if ps.ByName("community") != "" {
		state.GetCommunity(ps.ByName("community"))
		state.Op = "edit_community"
	}
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
func getCookie(r *http.Request, name string) string {
	cookie, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}
func setCookie(w http.ResponseWriter, host string, name string, value string) {
	if host == "." {
		host = ""
	}
	cookie := http.Cookie{
		Name:   name,
		Value:  value,
		MaxAge: 86400 * 30,
		Path:   "/" + host,
	}
	http.SetCookie(w, &cookie)
}
func deleteCookie(w http.ResponseWriter, host string, name string) {
	if host == "." {
		host = ""
	}
	cookie := http.Cookie{
		Name:   name,
		Path:   "/" + host,
		MaxAge: -1,
	}
	http.SetCookie(w, &cookie)
}
func Settings(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	state, err := Initialize(ps.ByName("host"), r)
	if err != nil {
		Render(w, "index.html", state)
		return
	}
	switch r.Method {
	case "POST":
		for _, name := range []string{"DefaultSortType", "DefaultListingType"} {
			setCookie(w, state.Host, name, r.FormValue(name))
		}
		if r.FormValue("darkmode") != "" {
			setCookie(w, state.Host, "Dark", "1")
			state.Dark = true
		} else {
			deleteCookie(w, state.Host, "Dark")
			state.Dark = false
		}
		if r.FormValue("shownsfw") != "" {
			setCookie(w, state.Host, "ShowNSFW", "1")
			state.ShowNSFW = true
		} else {
			deleteCookie(w, state.Host, "ShowNSFW")
			state.ShowNSFW = false
		}
		state.Listing = r.FormValue("DefaultListingType")
		state.Sort = r.FormValue("DefaultSortType")
		// TODO save user settings
	case "GET":
		if state.Session != nil {
			// TODO fetch user settings
		}
	}
	Render(w, "settings.html", state)
}

func SignUpOrLogin(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	state, err := Initialize(ps.ByName("host"), r)
	if err != nil {
		fmt.Println(err)
		Render(w, "index.html", state)
		return
	}
	var token string
	var username string
	switch r.FormValue("submit") {
	case "log in":
		login := types.Login{
			UsernameOrEmail: r.FormValue("username"),
			Password:        r.FormValue("password"),
		}
		if r.FormValue("totp") != "" {
			login.Totp2faToken = types.NewOptional(r.FormValue("totp"))
		}
		resp, err := state.Client.Login(context.Background(), login)
		if err != nil {
			if strings.Contains(fmt.Sprintf("%v", err), "missing_totp_token") {
				state.Op = "2fa"
			}
			fmt.Println(err)
			state.Error = err
			state.GetSite()
			state.GetCaptcha()
			Render(w, "login.html", state)
			return
		}
		if resp.JWT.IsValid() {
			token = resp.JWT.String()
			username = r.FormValue("username")
			deleteCookie(w, state.Host, "ShowNSFW")
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
			username = r.FormValue("username")
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
		state.GetUser(username)
		setCookie(w, state.Host, "jwt", token)
		userid := strconv.Itoa(state.User.PersonView.Person.ID)
		setCookie(w, state.Host, "user", state.User.PersonView.Person.Name+":"+userid)
		setCookie(w, state.Host, "jwt", token)
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
	if state.Site.SiteView.LocalSite.CaptchaEnabled {
		state.GetCaptcha()
	}
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
		state.GetCommunity(state.CommunityName)
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
		deleteCookie(w, state.Host, "jwt")
		deleteCookie(w, state.Host, "user")
	case "login":
		login := types.Login{
			UsernameOrEmail: r.FormValue("username"),
			Password:        r.FormValue("password"),
		}
		if r.FormValue("totp") != "" {
			login.Totp2faToken = types.NewOptional(r.FormValue("totp"))
		}
		resp, err := state.Client.Login(context.Background(), login)
		if err != nil {
			if strings.Contains(fmt.Sprintf("%v", err), "missing_totp_token") {
				state.Op = "2fa"
				Render(w, "login.html", state)
				return
			}
			state.Status = http.StatusUnauthorized
		} else if resp.JWT.IsValid() {
			state.GetUser(r.FormValue("username"))
			if state.User != nil {
				setCookie(w, state.Host, "jwt", resp.JWT.String())
				userid := strconv.Itoa(state.User.PersonView.Person.ID)
				setCookie(w, state.Host, "user", state.User.PersonView.Person.Name+":"+userid)
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
		if state.CommunityName == "" {
			state.CommunityName = r.FormValue("communityname")
		}
		state.GetCommunity(state.CommunityName)
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
			Name:   types.NewOptional(r.FormValue("name")),
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
	case "save_post":
		postid, _ := strconv.Atoi(r.FormValue("postid"))
		_, err := state.Client.SavePost(context.Background(), types.SavePost{
			PostID: postid,
			Save:   r.FormValue("submit") == "save",
		})
		if err != nil {
			fmt.Println(err)
		}
	case "save_comment":
		commentid, _ := strconv.Atoi(r.FormValue("commentid"))
		_, err := state.Client.SaveComment(context.Background(), types.SaveComment{
			CommentID: commentid,
			Save:      r.FormValue("submit") == "save",
		})
		if err != nil {
			fmt.Println(err)
		}
		if r.FormValue("xhr") != "" {
			state.XHR = true
			state.GetComment(commentid)
			Render(w, "index.html", state)
			return
		}
	case "delete_post":
		postid, _ := strconv.Atoi(r.FormValue("postid"))
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
		if r.FormValue("xhr") != "" {
			state.GetPost(postid)
			state.XHR = true
			Render(w, "index.html", state)
			return
		}
	case "vote_comment":
		var score int16
		score = 1
		if r.FormValue("submit") != "▲" {
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
		if r.FormValue("xhr") != "" {
			state.XHR = true
			state.GetComment(commentid)
			Render(w, "index.html", state)
			return
		}
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
	case "shownsfw":
		if r.FormValue("submit") == "continue" {
			setCookie(w, state.Host, "ShowNSFW", "1")
		} else {
			r.URL.Path = "/" + state.Host
		}
	}
	http.Redirect(w, r, r.URL.String(), 301)
}
func GetRouter() *httprouter.Router {
	host := os.Getenv("LEMMY_DOMAIN")
	router := httprouter.New()
	if host == "" {
		router.ServeFiles("/:host/static/*filepath", http.Dir("public"))
		router.GET("/", GetRoot)
		router.POST("/", PostRoot)
		router.GET("/:host/", middleware(GetFrontpage))
		router.GET("/:host/search", middleware(Search))
		router.POST("/:host/search", middleware(UserOp))
		router.GET("/:host/inbox", middleware(Inbox))
		router.GET("/:host/login", middleware(GetLogin))
		router.POST("/:host/login", middleware(SignUpOrLogin))
		router.GET("/:host/settings", middleware(Settings))
		router.POST("/:host/settings", middleware(Settings))
		router.POST("/:host/", middleware(UserOp))
		router.GET("/:host/icon.jpg", middleware(GetIcon))
		router.GET("/:host/c/:community", middleware(GetFrontpage))
		router.POST("/:host/c/:community", middleware(UserOp))
		router.GET("/:host/c/:community/search", middleware(Search))
		router.GET("/:host/c/:community/edit", middleware(GetCreateCommunity))
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
	} else {
		router.ServeFiles("/_/static/*filepath", http.Dir("public"))
		router.GET("/", middleware(GetFrontpage))
		router.GET("/search", middleware(Search))
		router.POST("/search", middleware(UserOp))
		router.GET("/inbox", middleware(Inbox))
		router.GET("/login", middleware(GetLogin))
		router.POST("/login", middleware(SignUpOrLogin))
		router.GET("/settings", middleware(Settings))
		router.POST("/settings", middleware(Settings))
		router.POST("/", middleware(UserOp))
		router.GET("/icon.jpg", middleware(GetIcon))
		router.GET("/c/:community", middleware(GetFrontpage))
		router.POST("/c/:community", middleware(UserOp))
		router.GET("/c/:community/search", middleware(Search))
		router.GET("/c/:community/edit", middleware(GetCreateCommunity))
		router.GET("/post/:postid", middleware(GetPost))
		router.POST("/post/:postid", middleware(UserOp))
		router.GET("/comment/:commentid", middleware(GetComment))
		router.GET("/comment/:commentid/:op", middleware(GetComment))
		router.POST("/comment/:commentid", middleware(UserOp))
		router.GET("/u/:username", middleware(GetUser))
		router.GET("/u/:username/message", middleware(GetMessageForm))
		router.POST("/u/:username/message", middleware(SendMessage))
		router.POST("/u/:username", middleware(UserOp))
		router.GET("/u/:username/search", middleware(Search))
		router.GET("/create_post", middleware(GetCreatePost))
		router.POST("/create_post", middleware(UserOp))
		router.GET("/create_community", middleware(GetCreateCommunity))
		router.POST("/create_community", middleware(UserOp))
	}
	return router
}
