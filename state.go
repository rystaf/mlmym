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
	UserName string
	UserID   int
}

type State struct {
	Client         *lemmy.Client
	HTTPClient     *http.Client
	Session        *Session
	Status         int
	Error          error
	Alert          string
	Host           string
	CommunityName  string
	Community      *types.GetCommunityResponse
	TopCommunities []types.CommunityView
	Communities    []types.CommunityView
	UnreadCount    int64
	Sort           string
	Listing        string
	Page           int
	Parts          []string
	Posts          []Post
	Comments       []Comment
	Activities     []Activity
	CommentCount   int
	PostID         int
	CommentID      int
	UserName       string
	User           *types.GetPersonDetailsResponse
	Now            int64
	XHR            bool
	Op             string
	Site           *types.GetSiteResponse
	Query          string
	SearchType     string
	Captcha        *types.CaptchaResponse
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
	var listing string
	if p.Listing != "All" {
		listing = "&listingType=" + p.Listing
	}
	var q string
	if p.Query != "" || p.SearchType == "Communities" {
		q = "q=" + p.Query + "&communityname=" + p.CommunityName + "&username=" + p.UserName + "&searchtype=" + p.SearchType + "&"
	}
	page := strconv.Itoa(p.Page - 1)
	return "?" + q + "sort=" + p.Sort + listing + "&page=" + page
}
func (p State) NextPage() string {
	var listing string
	if p.Listing != "All" {
		listing = "&listingType=" + p.Listing
	}
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
	//if len(m["op"]) > 0 {
	//	state.Op = m["op"][0]
	//}
	if len(m["page"]) > 0 {
		i, _ := strconv.Atoi(m["page"][0])
		state.Page = i
	}
}

//func (state *State) Build() {
//	if state.Listing == "" {
//		state.Listing = "All"
//	}
//	if state.Op == "create_post" {
//		if state.CommunityName != "" {
//			state.GetCommunity()
//		}
//		return
//	}
//	if state.CommentID > 0 {
//		state.GetComment()
//		state.GetPost()
//		state.GetCommunity()
//		return
//	}
//
//	if state.UserName != "" {
//		state.GetUser()
//		return
//	}
//
//	if state.PostID == 0 {
//		state.GetPosts()
//	} else {
//		state.GetPost()
//		state.GetComments()
//	}
//
//	if state.CommunityName != "" {
//		state.GetCommunity()
//	}
//
//}

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
	token := state.Client.Token
	state.Client.Token = ""
	resp, err := state.Client.Site(context.Background(), types.GetSite{})
	if err != nil {
		fmt.Println(err)
		state.Status = http.StatusInternalServerError
		return
	}
	state.Client.Token = token
	state.Site = resp
}

func (state *State) GetComment(commentid int) {
	state.CommentID = commentid
	cresp, err := state.Client.Comments(context.Background(), types.GetComments{
		ParentID: types.NewOptional(state.CommentID),
		Sort:     types.NewOptional(types.CommentSortType(state.Sort)),
		Type:     types.NewOptional(types.ListingType("All")),
		Limit:    types.NewOptional(int64(200)),
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
}
func (state *State) GetComments() {
	cresp, err := state.Client.Comments(context.Background(), types.GetComments{
		PostID: types.NewOptional(state.PostID),
		Sort:   types.NewOptional(types.CommentSortType(state.Sort)),
		Type:   types.NewOptional(types.ListingType("All")),
		Limit:  types.NewOptional(int64(200)),
		Page:   types.NewOptional(int64(state.Page)),
	})
	if err != nil {
		state.Status = http.StatusInternalServerError
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
		Username: types.NewOptional(state.UserName),
		Page:     types.NewOptional(int64(state.Page)),
		Limit:    types.NewOptional(int64(limit)),
	})
	if err != nil {
		fmt.Println(err)
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
		fmt.Println(err)
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
	resp, err := state.Client.Posts(context.Background(), types.GetPosts{
		Sort:          types.NewOptional(types.SortType(state.Sort)),
		Type:          types.NewOptional(types.ListingType(state.Listing)),
		CommunityName: types.NewOptional(state.CommunityName),
		Limit:         types.NewOptional(int64(25)),
		Page:          types.NewOptional(int64(state.Page)),
	})
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
		resp, err := state.Client.Communities(context.Background(), types.ListCommunities{
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
		ListingType: types.NewOptional(types.ListingType("All")),
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
			state.Comments = append(state.Comments, Comment{
				P:     c,
				State: state,
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
		return
	} else {
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
}

func (state *State) GetCommunity(communityName string) {
	if communityName != "" {
		state.CommunityName = communityName
	}
	if state.CommunityName == "" {
		return
	}
	fmt.Println("Get community " + state.CommunityName)
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
	total := -1
	for _, c := range pool {
		levels := strings.Split(c.Comment.Path, ".")
		for i, l := range levels {
			id, _ := strconv.Atoi(l)
			if id == parent.P.Comment.ID {
				total = total + 1
				if i == (len(levels) - 2) {
					children = append(children, Comment{
						P:     c,
						C:     children,
						State: parent.State,
					})
				}
			}

		}
	}
	for i, _ := range children {
		getChildren(&children[i], pool, postCreatorID)
	}
	parent.C = children
	parent.ChildCount = total
}
