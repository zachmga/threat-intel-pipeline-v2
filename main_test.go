package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testStore(t *testing.T) *sql.DB {
	t.Helper()
	db, err := openStore(filepath.Join(t.TempDir(), "intel.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestExistingSQLiteRecordRemainsReviewed(t *testing.T) {
	db := testStore(t)
	_, err := db.Exec(`INSERT INTO items(source,external_id,title,url,author,published_at,text,score,matched_terms,content_hash,first_seen,last_seen,reviewed) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, "IFIN", "42", "Report", "https://example.test/42", "alice", "2026-11-13T10:00:00+00:00", "Body", 0, "[]", "python-hash", "2026-11-13T10:00:00+00:00", "2026-11-13T10:00:00+00:00", 1)
	if err != nil {
		t.Fatal(err)
	}
	item := Item{Source: "IFIN", ExternalID: "42", Title: "Report", URL: "https://example.test/42", Author: "alice", PublishedAt: "2026-11-13T10:00:00Z", Text: "Body"}
	change, err := saveItem(db, &item, nil)
	if err != nil {
		t.Fatal(err)
	}
	if change != "unchanged" {
		t.Fatalf("change=%s", change)
	}
	var reviewed int
	if err := db.QueryRow(`SELECT reviewed FROM items WHERE id=?`, item.ID).Scan(&reviewed); err != nil {
		t.Fatal(err)
	}
	if reviewed != 1 {
		t.Fatalf("reviewed=%d", reviewed)
	}
}

func TestDiscourseTopicActivityFields(t *testing.T) {
	var topic discourseTopic
	if err := json.Unmarshal([]byte(`{"id":72,"category_id":5,"title":"Report","last_posted_at":"2026-11-14T20:00:00Z","created_at":"2026-11-13T10:00:00Z"}`), &topic); err != nil {
		t.Fatal(err)
	}
	if topic.LastPostedAt != "2026-11-14T20:00:00Z" || topic.CreatedAt != "2026-11-13T10:00:00Z" || topic.CategoryID != 5 {
		t.Fatalf("topic=%+v", topic)
	}
}

func TestFeedParsers(t *testing.T) {
	rss := []byte(`<rss version="2.0"><channel><item><guid>one</guid><title>Leak claim</title><link>https://example.test/one</link><pubDate>Fri, 13 Nov 2026 22:46:01 +0000</pubDate><description><![CDATA[<p>Claim &amp; context</p>]]></description></item></channel></rss>`)
	var got []Item
	emit := func(item Item) error { got = append(got, item); return nil }
	if err := parseFeed(rss, Source{Name: "RSS", URL: "https://example.test/feed"}, emit); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ExternalID != "one" || got[0].Text != "Claim & context" {
		t.Fatalf("rss=%+v", got)
	}
	atom := []byte(`<feed xmlns="http://www.w3.org/2005/Atom"><entry><id>tag:one</id><title>Malware</title><link rel="alternate" href="/post/1"/><updated>2026-11-13T22:00:00Z</updated><summary type="html">&lt;p&gt;Observed&lt;/p&gt;</summary></entry></feed>`)
	got = nil
	if err := parseFeed(atom, Source{Name: "Atom", URL: "https://example.test/feed"}, emit); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].URL != "https://example.test/post/1" || got[0].Text != "Observed" {
		t.Fatalf("atom=%+v", got)
	}
}

func TestMastodonPublicFiltersAndCursor(t *testing.T) {
	hits := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		hits++
		if r.URL.Path != "/api/v1/timelines/public" || r.URL.Query().Get("local") != "true" || r.URL.Query().Get("limit") != "40" {
			t.Errorf("query=%s", r.URL.String())
		}
		body := `[{"id":"102","created_at":"2026-11-13T22:00:00Z","content":"<p>CVE-2026-1234 analysis</p>","url":"https://example.test/@alice/102","visibility":"public","account":{"acct":"alice"}},{"id":"101","created_at":"2026-11-13T21:00:00Z","content":"<p>Lunch</p>","url":"https://example.test/@bob/101","visibility":"public","account":{"acct":"bob"}}]`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	c := newCollector(testStore(t), nil, t.TempDir())
	c.PublicClient = client
	s := Source{Name: "InfoSec Exchange", Kind: "mastodon_public", BaseURL: "https://infosec.exchange", MaxPages: 2, Keywords: []string{"cve-"}}
	var got []Item
	partial, cursor, err := c.mastodonPublic(s, func(item Item) error { got = append(got, item); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if partial || cursor != "102" || len(got) != 1 || got[0].Author != "alice" || hits != 1 {
		t.Fatalf("partial=%v cursor=%q items=%+v hits=%d", partial, cursor, got, hits)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOnionHTMLStaysOnConfiguredHost(t *testing.T) {
	host := strings.Repeat("a", 56) + ".onion"
	s := Source{Name: "Onion", Kind: "onion_html", URL: "http://" + host + "/", EntryTag: "article"}
	if err := validateOnionURL(s.URL); err != nil {
		t.Fatal(err)
	}
	if err := validateOnionURL("https://example.com/"); err == nil {
		t.Fatal("accepted clearnet URL")
	}
	page := []byte(`<html><article><a href="/post/one">Victim claim</a><time datetime="2026-11-13T20:00:00Z"></time><p>Unverified actor statement</p></article><article><a href="https://example.com/offsite">Skip</a></article><article><a href="/files.zip">Skip download</a></article></html>`)
	var got []Item
	if err := parseOnionHTML(page, s, func(item Item) error { got = append(got, item); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].URL != "http://"+host+"/post/one" || got[0].PublishedAt != "2026-11-13T20:00:00Z" {
		t.Fatalf("items=%+v", got)
	}
}

func TestMinimumPollInterval(t *testing.T) {
	recent := time.Now().UTC().Add(-20 * time.Minute).Format(time.RFC3339)
	old := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	if shouldPoll(SourceState{LastSuccess: &recent}, 55) {
		t.Fatal("polled too soon")
	}
	if !shouldPoll(SourceState{LastSuccess: &old}, 55) {
		t.Fatal("skipped old poll")
	}
}

func TestSampledTimelineAdvancesCursorAndMarksCoverage(t *testing.T) {
	posts := make([]string, 0, 40)
	for id := 100; id > 60; id-- {
		posts = append(posts, fmt.Sprintf(`{"id":"%d","created_at":"2026-11-13T22:00:00Z","content":"<p>CVE-2026-1234</p>","url":"https://infosec.exchange/@alice/%d","visibility":"public","account":{"acct":"alice"}}`, id, id))
	}
	body := "[" + strings.Join(posts, ",") + "]"
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	db := testStore(t)
	c := newCollector(db, map[string]int{"cve-": 1}, t.TempDir())
	c.PublicClient = client
	s := Source{Name: "InfoSec Exchange sampled", Kind: "mastodon_public", BaseURL: "https://infosec.exchange", MaxPages: 1, Sampled: true, Keywords: []string{"cve-"}}
	changes, results := c.run([]Source{s}, false)
	if len(changes) != 40 || len(results) != 1 || results[0].Status != "sampled" {
		t.Fatalf("changes=%d results=%+v", len(changes), results)
	}
	state, err := readSourceState(db, s.Name)
	if err != nil {
		t.Fatal(err)
	}
	if state.Cursor == nil || *state.Cursor != "100" || state.Partial != 1 {
		t.Fatalf("state=%+v", state)
	}
}
