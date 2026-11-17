package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

func (c *Collector) xRecent(source Source, emit func(Item) error) (bool, string, error) {
	token := strings.TrimSpace(os.Getenv("X_BEARER_TOKEN"))
	if token == "" {
		data, err := os.ReadFile(filepath.Join(c.Root, ".secrets", "x_bearer_token"))
		if err == nil {
			token = strings.TrimSpace(string(data))
		}
	}
	if token == "" {
		return false, "", fmt.Errorf("X bearer token missing; set X_BEARER_TOKEN or .secrets/x_bearer_token")
	}
	state, err := readSourceState(c.DB, source.Name)
	if err != nil {
		return false, "", err
	}
	cursor := ""
	if state.Cursor != nil {
		cursor = *state.Cursor
	}
	maxID := cursor
	nextToken := ""
	partial := false
	for page := 0; page < source.pages(3); page++ {
		q := url.Values{"query": {source.Query}, "max_results": {"100"}, "tweet.fields": {"created_at,author_id"}, "expansions": {"author_id"}, "user.fields": {"username,name"}}
		if cursor != "" {
			q.Set("since_id", cursor)
		}
		if nextToken != "" {
			q.Set("next_token", nextToken)
		}
		var raw struct {
			Data     []xPost `json:"data"`
			Includes struct {
				Users []xUser `json:"users"`
			} `json:"includes"`
			Meta struct {
				NextToken string `json:"next_token"`
			} `json:"meta"`
			Errors []json.RawMessage `json:"errors"`
		}
		if err := c.getJSON(source, "https://api.x.com/2/tweets/search/recent?"+q.Encode(), token, &raw); err != nil {
			return false, "", err
		}
		if len(raw.Errors) > 0 {
			return false, "", fmt.Errorf("X API returned %d errors", len(raw.Errors))
		}
		users := map[string]string{}
		for _, u := range raw.Includes.Users {
			users[u.ID] = u.Username
		}
		for _, p := range raw.Data {
			if stringIDGreater(p.ID, maxID) {
				maxID = p.ID
			}
			author := users[p.AuthorID]
			if author == "" {
				author = p.AuthorID
			}
			item := Item{Source: source.Name, ExternalID: p.ID, Title: truncated(p.Text, 120), URL: fmt.Sprintf("https://x.com/%s/status/%s", author, p.ID), Author: author, PublishedAt: p.CreatedAt, Text: p.Text}
			if err := emit(item); err != nil {
				return false, "", err
			}
		}
		nextToken = raw.Meta.NextToken
		if nextToken == "" {
			break
		}
		if page == source.pages(3)-1 {
			partial = true
		}
	}
	if partial {
		return true, "", nil
	}
	return false, maxID, nil
}

type xPost struct {
	ID        string `json:"id"`
	Text      string `json:"text"`
	CreatedAt string `json:"created_at"`
	AuthorID  string `json:"author_id"`
}
type xUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

type mastodonStatus struct {
	ID         string          `json:"id"`
	CreatedAt  string          `json:"created_at"`
	Content    string          `json:"content"`
	URL        string          `json:"url"`
	Visibility string          `json:"visibility"`
	Reblog     json.RawMessage `json:"reblog"`
	Account    struct {
		Acct     string `json:"acct"`
		Username string `json:"username"`
	} `json:"account"`
}

func keywordMatch(text string, keywords []string) bool {
	if len(keywords) == 0 {
		return true
	}
	low := strings.ToLower(text)
	for _, k := range keywords {
		if strings.Contains(low, strings.ToLower(k)) {
			return true
		}
	}
	return false
}

func (c *Collector) mastodonPublic(source Source, emit func(Item) error) (bool, string, error) {
	state, err := readSourceState(c.DB, source.Name)
	if err != nil {
		return false, "", err
	}
	cursor := ""
	if state.Cursor != nil {
		cursor = *state.Cursor
	}
	maxID := cursor
	pageCursor := ""
	partial := false
	base := strings.TrimRight(source.BaseURL, "/")
	for page := 0; page < source.pages(3); page++ {
		q := url.Values{"local": {"true"}, "limit": {"40"}}
		if cursor != "" {
			q.Set("since_id", cursor)
		}
		if pageCursor != "" {
			q.Set("max_id", pageCursor)
		}
		var statuses []mastodonStatus
		if err := c.getJSON(source, base+"/api/v1/timelines/public?"+q.Encode(), "", &statuses); err != nil {
			return false, "", err
		}
		if len(statuses) == 0 {
			break
		}
		for _, p := range statuses {
			if stringIDGreater(p.ID, maxID) {
				maxID = p.ID
			}
			if p.Visibility != "public" || (len(p.Reblog) > 0 && string(p.Reblog) != "null") {
				continue
			}
			body := cleanHTML(p.Content)
			if !keywordMatch(body, source.Keywords) {
				continue
			}
			author := p.Account.Acct
			if author == "" {
				author = p.Account.Username
			}
			item := Item{Source: source.Name, ExternalID: p.ID, Title: truncated(strings.ReplaceAll(body, "\n", " "), 120), URL: p.URL, Author: author, PublishedAt: p.CreatedAt, Text: body}
			if err := emit(item); err != nil {
				return false, "", err
			}
		}
		pageCursor = statuses[len(statuses)-1].ID
		if len(statuses) < 40 {
			break
		}
		if page == source.pages(3)-1 {
			partial = true
		}
	}
	if partial {
		if source.Sampled {
			return true, maxID, nil
		}
		return true, "", nil
	}
	return false, maxID, nil
}

func hasClass(n *html.Node, class string) bool {
	if class == "" {
		return true
	}
	for _, a := range n.Attr {
		if a.Key == "class" {
			for _, part := range strings.Fields(a.Val) {
				if part == class {
					return true
				}
			}
		}
	}
	return false
}

func nodeAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func firstAnchor(n *html.Node) *html.Node {
	if n.Type == html.ElementNode && n.Data == "a" && nodeAttr(n, "href") != "" {
		return n
	}
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		if found := firstAnchor(child); found != nil {
			return found
		}
	}
	return nil
}

func firstTime(n *html.Node) string {
	if n.Type == html.ElementNode && n.Data == "time" && nodeAttr(n, "datetime") != "" {
		return nodeAttr(n, "datetime")
	}
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		if found := firstTime(child); found != "" {
			return found
		}
	}
	return ""
}

func textOfNode(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && (node.Data == "script" || node.Data == "style") {
			return
		}
		if node.Type == html.TextNode {
			b.WriteString(node.Data)
			b.WriteByte(' ')
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(n)
	return strings.Join(strings.Fields(b.String()), " ")
}

var payloadSuffix = regexp.MustCompile(`(?i)\.(zip|rar|7z|exe|dll|dmg|pkg|pdf|torrent)(\?.*)?$`)

func parseOnionHTML(data []byte, source Source, emit func(Item) error) error {
	root, err := html.Parse(strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	origin, _ := url.Parse(source.URL)
	tag := source.EntryTag
	if tag == "" {
		tag = "article"
	}
	count := 0
	var walk func(*html.Node) error
	walk = func(n *html.Node) error {
		if count >= 50 {
			return nil
		}
		if n.Type == html.ElementNode && n.Data == tag && hasClass(n, source.EntryClass) {
			a := firstAnchor(n)
			if a != nil {
				link := resolveURL(source.URL, nodeAttr(a, "href"))
				u, err := url.Parse(link)
				if err == nil && strings.EqualFold(u.Hostname(), origin.Hostname()) && !payloadSuffix.MatchString(strings.ToLower(u.Path)) {
					title := textOfNode(a)
					if title == "" {
						title = textOfNode(n)
					}
					body := truncated(textOfNode(n), 1600)
					published := firstTime(n)
					if err := emit(Item{Source: source.Name, ExternalID: link, Title: truncated(title, 180), URL: link, PublishedAt: published, Text: body}); err != nil {
						return err
					}
					count++
				}
			}
			return nil
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(root)
}

func (c *Collector) onionHTML(source Source, emit func(Item) error) (bool, string, error) {
	data, err := c.fetch(source, source.URL, "")
	if err != nil {
		return false, "", err
	}
	return false, "", parseOnionHTML(data, source, emit)
}
