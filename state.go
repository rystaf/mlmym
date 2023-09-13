package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rystaf/go-lemmy"
	"github.com/rystaf/go-lemmy/types"
)

type Comment struct {
	P          types.CommentView
	C          []Comment
	Selected   bool
	State      *State
	Op         string
	ChildCount int
}

func (c *Comment) Submitter() bool {
	return c.P.Comment.CreatorID == c.P.Post.CreatorID
}

func (c *Comment) ParentID() int {
	path := strings.Split(c.P.Comment.Path, ".")
	id, _ := strconv.Atoi(path[len(path)-2])
	return id
}

type Person struct {
	types.PersonViewSafe
}

type Activity struct {
	Timestamp time.Time
	Comment   *Comment
	Post      *Post
	Message   *types.PrivateMessageView
}

type Post struct {
	types.PostView
	Rank  int
	State *State
}

type Session struct {
	UserName    string
	UserID      int
	Communities []types.CommunityView
}

type State struct {
	Watch             bool
	Version           string
	Client            *lemmy.Client
	HTTPClient        *http.Client
	Session           *Session
	Status            int
	Error             error
	Alert             string
	Host              string
	CommunityName     string
	Community         *types.GetCommunityResponse
	TopCommunities    []types.CommunityView
	Communities       []types.CommunityView
	UnreadCount       int64
	Sort              string
	CommentSort       string
	Listing           string
	Page              int
	Parts             []string
	Posts             []Post
	Comments          []Comment
	Activities        []Activity
	CommentCount      int
	PostID            int
	CommentID         int
	Context           int
	UserName          string
	User              *types.GetPersonDetailsResponse
	Now               int64
	XHR               bool
	Op                string
	Site              *types.GetSiteResponse
	Query             string
	Content           string
	SearchType        string
	Captcha           *types.CaptchaResponse
	Dark              bool
	ShowNSFW          bool
	HideInstanceNames bool
	HideThumbnails    bool
	LinksInNewWindow  bool
	SubmitURL         string
	SubmitTitle       string
	SubmitBody        string
}

func (s State) UserBlocked() bool {
	if s.User == nil || s.Site == nil || !s.Site.MyUser.IsValid() {
		return false
	}
	for _, p := range s.Site.MyUser.MustValue().PersonBlocks {
		if p.Target.ID == s.User.PersonView.Person.ID {
			return true
		}
	}
	return false
}

func (s State) Unknown() string {
	fmt.Println(fmt.Sprintf("%v", s.Error))
	re := regexp.MustCompile(`(.*?)@(.*?)@`)
	if strings.Contains(fmt.Sprintf("%v", s.Error), "couldnt_find_community") {
		matches := re.FindAllStringSubmatch(s.CommunityName+"@", -1)
		if len(matches) < 1 || len(matches[0]) < 3 {
			return ""
		}
		if matches[0][2] != s.Host {
			remote := "/" + matches[0][2] + "/c/" + matches[0][1]
			if os.Getenv("LEMMY_DOMAIN") != "" {
				remote = "https:/" + remote
			}
			return remote
		}
	}
	if strings.Contains(fmt.Sprintf("%v", s.Error), "couldnt_find_that_username_or_email") {
		matches := re.FindAllStringSubmatch(s.UserName+"@", -1)
		if len(matches) < 1 || len(matches[0]) < 3 {
			return ""
		}
		if matches[0][2] != s.Host {
			remote := "/" + matches[0][2] + "/u/" + matches[0][1]
			if os.Getenv("LEMMY_DOMAIN") != "" {
				remote = "https:/" + remote
			}
			return remote
		}
	}
	return ""
}
func (p State) SortBy(v string) string {
	var q string
	if p.Query != "" || p.SearchType == "Communities" {
		q = "q=" + p.Query + "&communityname=" + p.CommunityName + "&username=" + p.UserName + "&searchtype=" + p.SearchType + "&"
	}
	return "?" + q + "sort=" + v + "&listingType=" + p.Listing
}
func (p State) ListBy(v string) string {
	var q string
	if p.Query != "" || p.SearchType == "Communities" {
		q = "q=" + p.Query + "&communityname=" + p.CommunityName + "&username=" + p.UserName + "&searchtype=" + p.SearchType + "&"
	}
	return "?" + q + "sort=" + p.Sort + "&listingType=" + v
}

func (p State) PrevPage() string {
	listing := "&listingType=" + p.Listing
	var q string
	if p.Query != "" || p.SearchType == "Communities" {
		q = "q=" + p.Query + "&communityname=" + p.CommunityName + "&username=" + p.UserName + "&searchtype=" + p.SearchType + "&"
	}
	page := strconv.Itoa(p.Page - 1)
	return "?" + q + "sort=" + p.Sort + listing + "&page=" + page
}
func (p State) NextPage() string {
	listing := "&listingType=" + p.Listing
	var q string
	if p.Query != "" || p.SearchType == "Communities" {
		q = "q=" + p.Query + "&communityname=" + p.CommunityName + "&username=" + p.UserName + "&searchtype=" + p.SearchType + "&"
	}
	page := strconv.Itoa(p.Page + 1)
	return "?" + q + "sort=" + p.Sort + listing + "&page=" + page
}
func (p State) Rank(v int) int {
	return ((p.Page - 1) * 25) + v + 1
}

func (u *Person) FullUserName() string {
	if u.Person.Local {
		return u.Person.Name
	}
	l, err := url.Parse(u.Person.ActorID)
	if err != nil {
		fmt.Println(err)
		return u.Person.Name
	}
	return u.Person.Name + "@" + l.Host
}

func (state *State) ParseQuery(RawQuery string) {
	if RawQuery == "" {
		return
	}
	m, _ := url.ParseQuery(RawQuery)
	if len(m["listingType"]) > 0 {
		state.Listing = m["listingType"][0]
	}
	if len(m["sort"]) > 0 {
		state.Sort = m["sort"][0]
		state.CommentSort = m["sort"][0]
	}
	if len(m["communityname"]) > 0 {
		state.CommunityName = m["communityname"][0]
	}
	if len(m["username"]) > 0 {
		state.UserName = m["username"][0]
	}
	if len(m["q"]) > 0 {
		state.Query = m["q"][0]
	}
	if len(m["xhr"]) > 0 {
		state.XHR = true
	}
	if len(m["view"]) > 0 {
		if m["view"][0] == "Saved" {
			state.Op = "Saved"
		}
	}
	//if len(m["op"]) > 0 {
	//	state.Op = m["op"][0]
	//}
	if len(m["page"]) > 0 {
		i, _ := strconv.Atoi(m["page"][0])
		state.Page = i
	}
}

func (state *State) LemmyError(domain string) error {
	var nodeInfo NodeInfo
	res, err := state.HTTPClient.Get("https://" + domain + "/nodeinfo/2.0.json")
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("Status Code: %v", res.StatusCode)
	}
	err = json.NewDecoder(res.Body).Decode(&nodeInfo)
	if err != nil {
		return err
	}
	if nodeInfo.Software.Name == "lemmy" {
		return nil
	}
	return errors.New("Not a lemmy instance")
}

func (state *State) GetCaptcha() {
	resp, err := state.Client.Captcha(context.Background(), types.GetCaptcha{})
	if err != nil {
		fmt.Printf("Get %v %v", err, resp)
	} else {
		captcha, _ := resp.Ok.Value()
		if resp.Ok.IsValid() {
			state.Captcha = &captcha
		}
	}
}
func (state *State) GetSite() {
	resp, err := state.Client.Site(context.Background(), types.GetSite{})
	if err != nil {
		fmt.Println(err)
		state.Status = http.StatusInternalServerError
		state.Host = "."
		state.Error = errors.New("unable to retrieve site")
		return
	}
	state.Site = resp
	if !state.Site.MyUser.IsValid() {
		return
	}
	for _, c := range state.Site.MyUser.MustValue().Follows {
		state.Session.Communities = append(state.Session.Communities, types.CommunityView{
			Community:  c.Community,
			Subscribed: "Subscribed",
		})
	}
	sort.Slice(state.Session.Communities, func(a, b int) bool {
		return state.Session.Communities[a].Community.Name < state.Session.Communities[b].Community.Name
	})
}

func (state *State) GetComment(commentid int) {
	if state.Sort != "Hot" && state.Sort != "Top" && state.Sort != "Old" && state.Sort != "New" {
		state.Sort = "Hot"
	}
	state.CommentID = commentid
	cresp, err := state.Client.Comments(context.Background(), types.GetComments{
		ParentID: types.NewOptional(state.CommentID),
		Sort:     types.NewOptional(types.CommentSortType(state.CommentSort)),
		Type:     types.NewOptional(types.ListingType("All")),
		Limit:    types.NewOptional(int64(50)),
	})
	if err != nil {
		fmt.Println(err)
		state.Status = http.StatusInternalServerError
		return
	}
	state.CommentCount = len(cresp.Comments)
	for _, c := range cresp.Comments {
		if c.Comment.ID == state.CommentID {
			state.PostID = c.Comment.PostID
			//if state.Session != nil && state.Session.UserID
			comment := Comment{
				P:        c,
				Selected: !state.XHR,
				State:    state,
				Op:       state.Op,
			}
			getChildren(&comment, cresp.Comments, c.Post.CreatorID)
			state.Comments = append(state.Comments, comment)
		}
	}
	if len(state.Comments) == 0 {
		return
	}
	ctx, err := state.GetContext(state.Context, state.Comments[0])
	if err != nil {
		fmt.Println(err)
	} else {
		state.Comments = []Comment{ctx}
	}
}
func (state *State) GetContext(depth int, comment Comment) (ctx Comment, err error) {
	if depth < 1 || comment.ParentID() == 0 {
		return comment, nil
	}
	cresp, err := state.Client.Comment(context.Background(), types.GetComment{
		ID: comment.ParentID(),
	})
	if err != nil {
		return
	}
	ctx, err = state.GetContext(depth-1, Comment{
		P:          cresp.CommentView,
		State:      state,
		C:          []Comment{comment},
		ChildCount: comment.ChildCount + 1,
	})
	return
}
func (state *State) GetComments() {
	if state.Sort != "Hot" && state.Sort != "Top" && state.Sort != "Old" && state.Sort != "New" {
		state.Sort = "Hot"
	}
	cresp, err := state.Client.Comments(context.Background(), types.GetComments{
		PostID: types.NewOptional(state.PostID),
		Sort:   types.NewOptional(types.CommentSortType(state.CommentSort)),
		Type:   types.NewOptional(types.ListingType("All")),
		Limit:  types.NewOptional(int64(50)),
		Page:   types.NewOptional(int64(state.Page)),
	})
	if err != nil {
		state.Status = http.StatusInternalServerError
		fmt.Println(err)
		return
	}
	state.CommentCount = len(cresp.Comments)
	for _, c := range cresp.Comments {
		levels := strings.Split(c.Comment.Path, ".")
		if len(levels) != 2 {
			continue
		}
		comment := Comment{P: c, State: state}
		var postCreatorID int
		if len(state.Posts) > 0 {
			postCreatorID = state.Posts[0].Post.CreatorID
		}
		getChildren(&comment, cresp.Comments, postCreatorID)
		state.Comments = append(state.Comments, comment)
	}
}

func (state *State) GetMessages() {
	if resp, err := state.Client.PrivateMessages(context.Background(), types.GetPrivateMessages{
		Page: types.NewOptional(int64(state.Page)),
	}); err != nil {
		fmt.Println(err)
		state.Status = http.StatusInternalServerError
		return
	} else {
		for _, m := range resp.PrivateMessages {
			message := m
			state.Activities = append(state.Activities, Activity{
				Timestamp: m.PrivateMessage.Published.Time,
				Message:   &message,
			})
		}
	}
	if resp, err := state.Client.PersonMentions(context.Background(), types.GetPersonMentions{
		Page: types.NewOptional(int64(state.Page)),
	}); err != nil {
		fmt.Println(err)
		state.Status = http.StatusInternalServerError
		return
	} else {
		for _, m := range resp.Mentions {
			var unread string
			if !m.PersonMention.Read {
				unread = "unread"
			}
			comment := Comment{
				P: types.CommentView{
					Comment: m.Comment,
				},
				Op:    unread,
				State: state,
			}
			state.Activities = append(state.Activities, Activity{
				Timestamp: m.Comment.Published.Time,
				Comment:   &comment,
			})
		}
	}
	if resp, err := state.Client.Replies(context.Background(), types.GetReplies{
		Page: types.NewOptional(int64(state.Page)),
	}); err != nil {
		fmt.Println(err)
		state.Status = http.StatusInternalServerError
		return
	} else {
		for _, m := range resp.Replies {
			var unread string
			if !m.CommentReply.Read {
				unread = "unread"
			}
			comment := Comment{
				P: types.CommentView{
					Comment:   m.Comment,
					Post:      m.Post,
					Creator:   m.Creator,
					Community: m.Community,
					Counts:    m.Counts,
				},
				Op:    unread,
				State: state,
			}
			state.Activities = append(state.Activities, Activity{
				Timestamp: m.Comment.Published.Time,
				Comment:   &comment,
			})
		}
	}
}

func (state *State) GetUser(username string) {
	state.UserName = username
	limit := 12
	if state.Op == "send_message" {
		limit = 1
	}
	resp, err := state.Client.PersonDetails(context.Background(), types.GetPersonDetails{
		Username:  types.NewOptional(state.UserName),
		Page:      types.NewOptional(int64(state.Page)),
		Limit:     types.NewOptional(int64(limit)),
		SavedOnly: types.NewOptional(state.Op == "Saved"),
	})
	if err != nil {
		fmt.Println(err)
		state.Error = err
		state.Status = http.StatusInternalServerError
		return
	}
	state.User = resp
	if state.Query != "" {
		return
	}
	for i, p := range resp.Posts {
		post := Post{
			PostView: resp.Posts[i],
			Rank:     -1,
			State:    state,
		}
		state.Activities = append(state.Activities, Activity{
			Timestamp: p.Post.Published.Time,
			Post:      &post,
		})
	}
	for _, c := range resp.Comments {
		comment := Comment{P: c, State: state}
		state.Activities = append(state.Activities, Activity{
			Timestamp: c.Comment.Published.Time,
			Comment:   &comment,
		})
	}
	sort.Slice(state.Activities, func(i, j int) bool {
		return state.Activities[i].Timestamp.After(state.Activities[j].Timestamp)
	})
}

func (state *State) GetUnreadCount() {
	resp, err := state.Client.UnreadCount(context.Background(), types.GetUnreadCount{})
	if err != nil {
		fmt.Println(err)
		return
	}
	state.UnreadCount = resp.PrivateMessages + resp.Mentions + resp.Replies
}
func (state *State) GetCommunities() {
	resp, err := state.Client.Communities(context.Background(), types.ListCommunities{
		Sort:  types.NewOptional(types.SortType("TopAll")),
		Limit: types.NewOptional(int64(20)),
	})
	if err != nil {
		return
	}
	state.TopCommunities = resp.Communities
}
func (state *State) MarkAllAsRead() {
	_, err := state.Client.MarkAllAsRead(context.Background(), types.MarkAllAsRead{})
	if err != nil {
		fmt.Println(err)
		return
	}
}

func (state *State) GetPosts() {
	posts := types.GetPosts{
		Sort:  types.NewOptional(types.SortType(state.Sort)),
		Type:  types.NewOptional(types.ListingType(state.Listing)),
		Limit: types.NewOptional(int64(25)),
		Page:  types.NewOptional(int64(state.Page)),
	}
	if state.CommunityName != "" {
		posts.CommunityName = types.NewOptional(state.CommunityName)
	}
	resp, err := state.Client.Posts(context.Background(), posts)
	if err != nil {
		fmt.Println(err)
		state.Status = http.StatusInternalServerError
		return
	} else {
		for i, p := range resp.Posts {
			state.Posts = append(state.Posts, Post{
				PostView: p,
				Rank:     (state.Page-1)*25 + i + 1,
				State:    state,
			})
		}
	}
}

func (state *State) Search(searchtype string) {
	if state.Query == "" && searchtype == "Communities" {
		if state.Listing == "Subscribed" {
			if state.Page > 1 {
				return
			}
			if state.Site == nil {
				state.GetSite()
			}
			state.Communities = state.Session.Communities
			return
		}
		resp, err := state.Client.Communities(context.Background(), types.ListCommunities{
			Type:  types.NewOptional(types.ListingType(state.Listing)),
			Sort:  types.NewOptional(types.SortType(state.Sort)),
			Limit: types.NewOptional(int64(25)),
			Page:  types.NewOptional(int64(state.Page)),
		})
		if err != nil {
			fmt.Println(err)
			return
		}
		state.Communities = resp.Communities
		return
	}
	search := types.Search{
		Q:           state.Query,
		Sort:        types.NewOptional(types.SortType(state.Sort)),
		ListingType: types.NewOptional(types.ListingType(state.Listing)),
		Type:        types.NewOptional(types.SearchType(searchtype)),
		Limit:       types.NewOptional(int64(25)),
		Page:        types.NewOptional(int64(state.Page)),
	}

	if state.CommunityName != "" {
		search.CommunityName = types.NewOptional(state.CommunityName)
	}

	if state.User != nil {
		search.CreatorID = types.NewOptional(state.User.PersonView.Person.ID)
	}

	resp, err := state.Client.Search(context.Background(), search)
	if err != nil {
		fmt.Println(err)
		state.Status = http.StatusInternalServerError
		return
	} else {
		for i, p := range resp.Posts {
			state.Posts = append(state.Posts, Post{
				PostView: p,
				Rank:     (state.Page-1)*25 + i + 1,
				State:    state,
			})
		}
		for _, c := range resp.Comments {
			comment := Comment{
				P:     c,
				State: state,
			}
			state.Activities = append(state.Activities, Activity{
				Timestamp: c.Comment.Published.Time,
				Comment:   &comment,
			})
		}
		state.Communities = resp.Communities
	}
}

func (state *State) GetPost(postid int) {
	if postid == 0 {
		return
	}
	state.PostID = postid
	// get post
	resp, err := state.Client.Post(context.Background(), types.GetPost{
		ID: types.NewOptional(state.PostID),
	})
	if err != nil {
		state.Status = http.StatusInternalServerError
		state.Error = err
		return
	}
	state.Posts = []Post{Post{
		PostView: resp.PostView,
		State:    state,
	}}
	if state.CommentID > 0 && len(state.Posts) > 0 {
		state.Posts[0].Rank = -1
	}
	state.CommunityName = resp.PostView.Community.Name
	cresp := types.GetCommunityResponse{
		CommunityView: resp.CommunityView,
		Moderators:    resp.Moderators,
	}
	state.Community = &cresp
}

func (state *State) GetCommunity(communityName string) {
	if communityName != "" {
		state.CommunityName = communityName
	}
	if state.CommunityName == "" {
		return
	}
	resp, err := state.Client.Community(context.Background(), types.GetCommunity{
		Name: types.NewOptional(state.CommunityName),
	})
	if err != nil {
		state.Error = err
	} else {
		state.Community = resp
	}
}

func (state *State) UploadImage(file multipart.File, header *multipart.FileHeader) (*PictrsResponse, error) {
	defer file.Close()
	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("images[]", header.Filename)
	if err != nil {
		return nil, err
	}
	io.Copy(part, file)
	writer.Close()
	req, err := http.NewRequest("POST", "https://"+state.Host+"/pictrs/image", body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Cookie", "jwt="+state.Client.Token)
	res, err := state.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var pres PictrsResponse
	if err := json.NewDecoder(res.Body).Decode(&pres); err != nil {
		return nil, err
	}
	if pres.Message != "ok" {
		return &pres, errors.New(pres.Message)
	}
	return &pres, nil
}

func getChildren(parent *Comment, pool []types.CommentView, postCreatorID int) {
	var children []Comment
	total := int32(0)
	for _, c := range pool {
		levels := strings.Split(c.Comment.Path, ".")
		for i, l := range levels {
			id, _ := strconv.Atoi(l)
			if id == parent.P.Comment.ID {
				if i == (len(levels) - 2) {
					children = append(children, Comment{
						P:     c,
						C:     children,
						State: parent.State,
					})
					total += c.Counts.ChildCount
				}
			}

		}
	}
	for i, _ := range children {
		getChildren(&children[i], pool, postCreatorID)
		parent.ChildCount += 1
	}
	parent.C = children
	parent.P.Counts.ChildCount -= total
}
