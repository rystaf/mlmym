package main

import (
	"net/http"
	"os"
	"strings"

	"golang.org/x/net/html"
)

func divHasError(n *html.Node) (result bool) {
	for _, a := range n.Attr {
		if a.Key == "class" && a.Val == "error" {
			if n.FirstChild.Type == html.TextNode && strings.Contains(n.FirstChild.Data, "unable to retrieve site") {
				return true
			}
		}
	}
	return false
}

func bodyHasError(n *html.Node) (result bool) {
	if n.Type == html.ElementNode && n.Data == "div" {
		if divHasError(n) {
			return true
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if bodyHasError(c) {
			return true
		}
	}
	return false
}

func main() {
	resp, err := http.Get("http://127.0.0.1:8080")
	if err != nil {
		os.Exit(1)
	}
	defer resp.Body.Close()

	doc, err := html.Parse(resp.Body)
	if err != nil {
		os.Exit(1)
	}
	if bodyHasError(doc) {
		os.Exit(1)
	}
}
