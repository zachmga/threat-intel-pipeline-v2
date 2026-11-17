package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS items (
  id INTEGER PRIMARY KEY,
  source TEXT NOT NULL,
  external_id TEXT NOT NULL,
  title TEXT NOT NULL,
  url TEXT NOT NULL,
  author TEXT NOT NULL,
  published_at TEXT NOT NULL,
  text TEXT NOT NULL,
  score INTEGER NOT NULL,
  matched_terms TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  reviewed INTEGER NOT NULL DEFAULT 0,
  UNIQUE(source, external_id)
);
CREATE INDEX IF NOT EXISTS items_review_order ON items(reviewed, score DESC, published_at DESC);
CREATE TABLE IF NOT EXISTS source_state (
  source TEXT PRIMARY KEY,
  cursor TEXT,
  last_success TEXT,
  last_error TEXT,
  partial INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS topic_state (
  source TEXT NOT NULL,
  topic_id INTEGER NOT NULL,
  last_posted_at TEXT NOT NULL,
  PRIMARY KEY(source, topic_id)
);`

type Item struct {
	ID          int64    `json:"id"`
	Source      string   `json:"source"`
	ExternalID  string   `json:"external_id,omitempty"`
	Title       string   `json:"title"`
	URL         string   `json:"url"`
	Author      string   `json:"author"`
	PublishedAt string   `json:"published_at"`
	Text        string   `json:"text"`
	Score       int      `json:"score"`
	Matched     []string `json:"matched_terms,omitempty"`
	Change      string   `json:"change,omitempty"`
}

type SourceState struct {
	Source      string  `json:"source"`
	Cursor      *string `json:"cursor"`
	LastSuccess *string `json:"last_success"`
	LastError   *string `json:"last_error"`
	Partial     int     `json:"partial"`
}

func utcNow() string { return time.Now().UTC().Format("2006-01-02T15:04:05+00:00") }

func normalizeTime(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return utcNow(), nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC1123Z, time.RFC1123, time.RFC822Z, time.RFC822, "2006-01-02 15:04:05 -0700", "2006-01-02"} {
		if t, err := time.Parse(layout, value); err == nil {
			return t.UTC().Format("2006-01-02T15:04:05+00:00"), nil
		}
	}
	return "", fmt.Errorf("invalid timestamp %q", value)
}

func openStore(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func scoreItem(title, body string, weights map[string]int) (int, []string) {
	haystack := strings.ToLower(title + "\n" + body)
	terms := make([]string, 0, len(weights))
	for term := range weights {
		terms = append(terms, term)
	}
	sort.Strings(terms)
	score, matches := 0, []string{}
	for _, term := range terms {
		if strings.Contains(haystack, strings.ToLower(term)) {
			score += weights[term]
			matches = append(matches, term)
		}
	}
	return score, matches
}

func saveItem(db *sql.DB, item *Item, weights map[string]int) (string, error) {
	if item.Source == "" || item.ExternalID == "" || item.Title == "" {
		return "", fmt.Errorf("item missing source, external ID, or title")
	}
	var err error
	item.PublishedAt, err = normalizeTime(item.PublishedAt)
	if err != nil {
		return "", err
	}
	item.Score, item.Matched = scoreItem(item.Title, item.Text, weights)
	var oldID int64
	var oldTitle, oldText, oldURL string
	err = db.QueryRow(`SELECT id,title,text,url FROM items WHERE source=? AND external_id=?`, item.Source, item.ExternalID).Scan(&oldID, &oldTitle, &oldText, &oldURL)
	if err != nil && err != sql.ErrNoRows {
		return "", err
	}
	seen := utcNow()
	if err == nil && oldTitle == item.Title && oldText == item.Text && oldURL == item.URL {
		item.ID = oldID
		_, err = db.Exec(`UPDATE items SET last_seen=? WHERE id=?`, seen, oldID)
		return "unchanged", err
	}
	parts, _ := json.Marshal([]string{item.Title, item.Text, item.URL})
	hash := sha256.Sum256(parts)
	matched, _ := json.Marshal(item.Matched)
	if err == sql.ErrNoRows {
		res, err := db.Exec(`INSERT INTO items(source,external_id,title,url,author,published_at,text,score,matched_terms,content_hash,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, item.Source, item.ExternalID, item.Title, item.URL, item.Author, item.PublishedAt, item.Text, item.Score, string(matched), hex.EncodeToString(hash[:]), seen, seen)
		if err != nil {
			return "", err
		}
		item.ID, err = res.LastInsertId()
		return "new", err
	}
	item.ID = oldID
	_, err = db.Exec(`UPDATE items SET title=?,url=?,author=?,published_at=?,text=?,score=?,matched_terms=?,content_hash=?,last_seen=?,reviewed=0 WHERE id=?`, item.Title, item.URL, item.Author, item.PublishedAt, item.Text, item.Score, string(matched), hex.EncodeToString(hash[:]), seen, oldID)
	return "updated", err
}

func readSourceState(db *sql.DB, name string) (SourceState, error) {
	state := SourceState{Source: name}
	err := db.QueryRow(`SELECT cursor,last_success,last_error,partial FROM source_state WHERE source=?`, name).Scan(&state.Cursor, &state.LastSuccess, &state.LastError, &state.Partial)
	if err == sql.ErrNoRows {
		return state, nil
	}
	return state, err
}

func writeSourceState(db *sql.DB, name, cursor, lastError string, partial bool) error {
	var success any
	if lastError == "" {
		success = utcNow()
	}
	var cur any
	if cursor != "" {
		cur = cursor
	}
	var errValue any
	if lastError != "" {
		errValue = lastError
	}
	_, err := db.Exec(`INSERT INTO source_state(source,cursor,last_success,last_error,partial) VALUES(?,?,?,?,?) ON CONFLICT(source) DO UPDATE SET cursor=COALESCE(excluded.cursor,source_state.cursor),last_success=COALESCE(excluded.last_success,source_state.last_success),last_error=excluded.last_error,partial=excluded.partial`, name, cur, success, errValue, boolInt(partial))
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
