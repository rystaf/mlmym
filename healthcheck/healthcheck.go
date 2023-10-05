package main

import (
	"io"
	"net/http"
	"os"
	"strings"
)

func main() {
	resp, err := http.Get("http://127.0.0.1:8080")
	if err != nil {
		os.Exit(1)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		os.Exit(1)
	}
	if strings.Contains(string(body), "unable to retrieve site") {
		os.Exit(1)
	}
}
