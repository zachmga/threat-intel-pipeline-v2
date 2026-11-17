package main

import (
	"database/sql"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/html"
)

const userAgent = "PersonalThreatIntelResearch/1.0 (+read-only research collector)"
const responseLimit = 8_000_000

type Source struct {
	Name               string   `json:"name"`
	Kind               string   `json:"kind"`
	URL                string   `json:"url,omitempty"`
	BaseURL            string   `json:"base_url,omitempty"`
	CategorySlug       string   `json:"category_slug,omitempty"`
	CategoryID         int      `json:"category_id,omitempty"`
	Query              string   `json:"query,omitempty"`
	MaxPages           int      `json:"max_pages,omitempty"`
	MinIntervalMinutes int      `json:"min_interval_minutes,omitempty"`
	Keywords           []string `json:"keywords,omitempty"`
	TorProxy           string   `json:"tor_proxy,omitempty"`
	EntryTag           string   `json:"entry_tag,omitempty"`
	EntryClass         string   `json:"entry_class,omitempty"`
	Sampled            bool     `json:"sampled,omitempty"`
	Enabled            *bool    `json:"enabled,omitempty"`
}

type discoursePost struct {
	ID         int    `json:"id"`
	PostNumber int    `json:"post_number"`
	Username   string `json:"username"`
	CreatedAt  string `json:"created_at"`
	Cooked     string `json:"cooked"`
	Raw        string `json:"raw"`
}

type discourseTopic struct {
	ID           int    `json:"id"`
	CategoryID   int    `json:"category_id"`
	Title        string `json:"title"`
	LastPostedAt string `json:"last_posted_at"`
	CreatedAt    string `json:"created_at"`
}

func (s Source) isEnabled() bool { return s.Enabled == nil || *s.Enabled }
func (s Source) pages(fallback int) int {
	if s.MaxPages > 0 {
		return s.MaxPages
	}
	return fallback
}

type Collector struct {
	DB           *sql.DB
	Weights      map[string]int
	Root         string
	PublicClient *http.Client
}

func newCollector(db *sql.DB, weights map[string]int, root string) *Collector {
	return &Collector{DB: db, Weights: weights, Root: root, PublicClient: &http.Client{Timeout: 25 * time.Second}}
}

func (c *Collector) clientFor(source Source) (*http.Client, error) {
	if source.Kind != "onion_feed" && source.Kind != "onion_html" {
		return c.PublicClient, nil
	}
	if err := validateOnionURL(source.URL); err != nil {
		return nil, err
	}
	proxyAddress := source.TorProxy
	if proxyAddress == "" {
		proxyAddress = "socks5h://127.0.0.1:9050"
	}
	proxyURL, err := url.Parse(proxyAddress)
	if err != nil || (proxyURL.Scheme != "socks5" && proxyURL.Scheme != "socks5h") || proxyURL.Host == "" {
		return nil, fmt.Errorf("Tor proxy must be a socks5h:// or socks5:// URL")
	}
	origin, _ := url.Parse(source.URL)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), MaxIdleConnsPerHost: 1, DisableKeepAlives: true}
	return &http.Client{Transport: transport, Timeout: 45 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || !strings.EqualFold(req.URL.Hostname(), origin.Hostname()) {
			return fmt.Errorf("onion redirect left configured host")
		}
		return nil
	}}, nil
}

var onionV3 = regexp.MustCompile(`^[a-z2-7]{56}\.onion$`)

func validateOnionURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !onionV3.MatchString(strings.ToLower(u.Hostname())) || u.User != nil {
		return fmt.Errorf("onion source must use an http(s) v3 .onion URL without credentials")
	}
	return nil
}

func (c *Collector) fetch(source Source, rawURL, token string) ([]byte, error) {
	client, err := c.clientFor(source)
	if err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", "application/json, application/rss+xml, application/atom+xml, application/xml, text/xml, text/html")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("network error for %s: %w", rawURL, err)
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, responseLimit+1))
		resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if len(data) > responseLimit {
			return nil, fmt.Errorf("response too large: %s", rawURL)
		}
		if resp.StatusCode == 429 {
			return nil, fmt.Errorf("HTTP 429 rate limited for %s", rawURL)
		}
		if resp.StatusCode >= 500 && attempt == 0 {
			time.Sleep(time.Second)
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("HTTP %d for %s", resp.StatusCode, rawURL)
		}
		return data, nil
	}
	return nil, fmt.Errorf("request failed: %s", rawURL)
}

func (c *Collector) getJSON(source Source, rawURL, token string, dest any) error {
	data, err := c.fetch(source, rawURL, token)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, dest)
}

func cleanHTML(raw string) string {
	node, err := html.Parse(strings.NewReader(raw))
	if err != nil {
		return strings.TrimSpace(raw)
	}
	var b strings.Builder
	var walk func(*html.Node, bool)
	walk = func(n *html.Node, skip bool) {
		if n.Type == html.ElementNode {
			if n.Data == "script" || n.Data == "style" {
				skip = true
			}
			if n.Data == "p" || n.Data == "br" || n.Data == "li" || n.Data == "div" {
				b.WriteByte('\n')
			}
		}
		if n.Type == html.TextNode && !skip {
			b.WriteString(n.Data)
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child, skip)
		}
		if n.Type == html.ElementNode && (n.Data == "p" || n.Data == "li" || n.Data == "div") {
			b.WriteByte('\n')
		}
	}
	walk(node, false)
	lines := []string{}
	for _, line := range strings.Split(b.String(), "\n") {
		line = strings.Join(strings.Fields(line), " ")
		if line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

func truncated(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}
func stringIDGreater(a, b string) bool {
	if len(a) != len(b) {
		return len(a) > len(b)
	}
	return a > b
}

func (c *Collector) discourse(source Source, emit func(Item) error) (bool, string, error) {
	base := strings.TrimRight(source.BaseURL, "/")
	state, err := readSourceState(c.DB, source.Name)
	if err != nil {
		return false, "", err
	}
	previousScan := ""
	if state.LastSuccess != nil {
		previousScan = *state.LastSuccess
	}
	partial := false
	for page := 0; page < source.pages(2); page++ {
		var category struct {
			TopicList struct {
				Topics        []discourseTopic `json:"topics"`
				MoreTopicsURL string           `json:"more_topics_url"`
			} `json:"topic_list"`
		}
		endpoint := fmt.Sprintf("%s/c/%s/%d.json?page=%d", base, url.PathEscape(source.CategorySlug), source.CategoryID, page)
		if err := c.getJSON(source, endpoint, "", &category); err != nil {
			return false, "", err
		}
		oldest := ""
		for _, topic := range category.TopicList.Topics {
			if topic.CategoryID != 0 && topic.CategoryID != source.CategoryID {
				continue
			}
			activity := topic.LastPostedAt
			if activity == "" {
				activity = topic.CreatedAt
			}
			if activity != "" && (oldest == "" || activity < oldest) {
				oldest = activity
			}
			var known string
			err := c.DB.QueryRow(`SELECT last_posted_at FROM topic_state WHERE source=? AND topic_id=?`, source.Name, topic.ID).Scan(&known)
			if err != nil && err != sql.ErrNoRows {
				return false, "", err
			}
			if known == activity && err == nil {
				continue
			}
			var detail struct {
				Title      string `json:"title"`
				PostStream struct {
					Stream []int           `json:"stream"`
					Posts  []discoursePost `json:"posts"`
				} `json:"post_stream"`
			}
			if err := c.getJSON(source, fmt.Sprintf("%s/t/%d.json", base, topic.ID), "", &detail); err != nil {
				return false, "", err
			}
			posts := map[int]discoursePost{}
			for _, p := range detail.PostStream.Posts {
				posts[p.ID] = p
			}
			missing := []int{}
			for _, id := range detail.PostStream.Stream {
				if _, ok := posts[id]; !ok {
					missing = append(missing, id)
				}
			}
			for start := 0; start < len(missing); start += 20 {
				end := start + 20
				if end > len(missing) {
					end = len(missing)
				}
				q := url.Values{}
				for _, id := range missing[start:end] {
					q.Add("post_ids[]", strconv.Itoa(id))
				}
				var extra struct {
					PostStream struct {
						Posts []discoursePost `json:"posts"`
					} `json:"post_stream"`
				}
				if err := c.getJSON(source, fmt.Sprintf("%s/t/%d/posts.json?%s", base, topic.ID, q.Encode()), "", &extra); err != nil {
					return false, "", err
				}
				for _, p := range extra.PostStream.Posts {
					posts[p.ID] = p
				}
			}
			ids := []int{}
			for id := range posts {
				ids = append(ids, id)
			}
			sortInts(ids)
			title := detail.Title
			if title == "" {
				title = topic.Title
			}
			if title == "" {
				title = "Untitled IFIN topic"
			}
			for _, id := range ids {
				p := posts[id]
				body := p.Cooked
				if body == "" {
					body = p.Raw
				}
				published := p.CreatedAt
				if published == "" {
					published = activity
				}
				item := Item{Source: source.Name, ExternalID: strconv.Itoa(p.ID), Title: title, URL: fmt.Sprintf("%s/t/%d/%d", base, topic.ID, p.PostNumber), Author: p.Username, PublishedAt: published, Text: cleanHTML(body)}
				if err := emit(item); err != nil {
					return false, "", err
				}
			}
			if _, err := c.DB.Exec(`INSERT INTO topic_state(source,topic_id,last_posted_at) VALUES(?,?,?) ON CONFLICT(source,topic_id) DO UPDATE SET last_posted_at=excluded.last_posted_at`, source.Name, topic.ID, activity); err != nil {
				return false, "", err
			}
		}
		if category.TopicList.MoreTopicsURL == "" {
			break
		}
		if page == source.pages(2)-1 && previousScan != "" && (oldest == "" || oldest > previousScan) {
			partial = true
		}
	}
	return partial, "", nil
}

func sortInts(values []int) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

type feedDoc struct {
	XMLName xml.Name
	Channel struct {
		Items []feedEntry `xml:"item"`
	} `xml:"channel"`
	Items   []feedEntry `xml:"item"`
	Entries []atomEntry `xml:"entry"`
}
type feedEntry struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	GUID        string `xml:"guid"`
	PubDate     string `xml:"pubDate"`
	Date        string `xml:"date"`
	Description string `xml:"description"`
	Encoded     string `xml:"encoded"`
	Creator     string `xml:"creator"`
}
type atomEntry struct {
	Title     string `xml:"title"`
	ID        string `xml:"id"`
	Published string `xml:"published"`
	Updated   string `xml:"updated"`
	Content   string `xml:"content"`
	Summary   string `xml:"summary"`
	Links     []struct {
		Href string `xml:"href,attr"`
		Rel  string `xml:"rel,attr"`
	} `xml:"link"`
	Author struct {
		Name string `xml:"name"`
	} `xml:"author"`
}

func parseFeed(data []byte, source Source, emit func(Item) error) error {
	var doc feedDoc
	if err := xml.Unmarshal(data, &doc); err != nil {
		return err
	}
	if doc.XMLName.Local == "feed" {
		for _, e := range doc.Entries {
			link := ""
			for _, l := range e.Links {
				if l.Rel == "alternate" || link == "" {
					link = l.Href
				}
			}
			published := e.Published
			if published == "" {
				published = e.Updated
			}
			body := e.Content
			if body == "" {
				body = e.Summary
			}
			id := e.ID
			if id == "" {
				id = link
			}
			if id == "" {
				id = e.Title + published
			}
			item := Item{Source: source.Name, ExternalID: id, Title: cleanHTML(e.Title), URL: resolveURL(source.URL, link), Author: e.Author.Name, PublishedAt: published, Text: cleanHTML(body)}
			if err := emit(item); err != nil {
				return err
			}
		}
		return nil
	}
	if doc.XMLName.Local != "rss" && doc.XMLName.Local != "RDF" {
		return fmt.Errorf("not an RSS or Atom feed: %s", source.URL)
	}
	entries := doc.Channel.Items
	if len(entries) == 0 {
		entries = doc.Items
	}
	for _, e := range entries {
		published := e.PubDate
		if published == "" {
			published = e.Date
		}
		id := e.GUID
		if id == "" {
			id = e.Link
		}
		if id == "" {
			id = e.Title + published
		}
		body := e.Description
		if body == "" {
			body = e.Encoded
		}
		item := Item{Source: source.Name, ExternalID: id, Title: cleanHTML(e.Title), URL: resolveURL(source.URL, e.Link), Author: e.Creator, PublishedAt: published, Text: cleanHTML(body)}
		if err := emit(item); err != nil {
			return err
		}
	}
	return nil
}

func resolveURL(base, link string) string {
	b, err := url.Parse(base)
	if err != nil {
		return link
	}
	r, err := url.Parse(link)
	if err != nil {
		return link
	}
	return b.ResolveReference(r).String()
}

func (c *Collector) feed(source Source, emit func(Item) error) (bool, string, error) {
	data, err := c.fetch(source, source.URL, "")
	if err != nil {
		return false, "", err
	}
	return false, "", parseFeed(data, source, emit)
}
