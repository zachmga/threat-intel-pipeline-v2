package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func writeJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func scanItem(rows *sql.Rows) (Item, error) {
	var item Item
	err := rows.Scan(&item.ID, &item.Source, &item.Title, &item.URL, &item.Author, &item.PublishedAt, &item.Text, &item.Score)
	return item, err
}

func writeDigest(db *sql.DB, output string, changes []Item, results []SourceResult) error {
	if err := os.MkdirAll(output, 0o700); err != nil {
		return err
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Score != changes[j].Score {
			return changes[i].Score > changes[j].Score
		}
		return changes[i].PublishedAt > changes[j].PublishedAt
	})
	payload := map[string]any{"generated_at": utcNow(), "results": results, "items": changes}
	if err := writeJSON(filepath.Join(output, "latest.json"), payload); err != nil {
		return err
	}
	lines := []string{"# New threat research findings", "", "Generated: " + utcNow(), "", fmt.Sprintf("New or updated: %d", len(changes)), "", "## Source health", ""}
	for _, r := range results {
		line := fmt.Sprintf("- %s: %s (%d changes)", r.Source, r.Status, r.Changes)
		if r.Error != "" {
			line += " - " + r.Error
		}
		lines = append(lines, line)
	}
	lines = append(lines, "", "## Findings", "")
	for _, item := range changes {
		title := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(item.Title, "\n", " "), "[", "\\["), "]", "\\]")
		lines = append(lines, fmt.Sprintf("### %d - %s", item.ID, title), "", fmt.Sprintf("- %s - score %d - %s - %s", item.Change, item.Score, item.Source, item.PublishedAt), "- Source: "+item.URL, "- Author: "+item.Author, "- Matched: "+strings.Join(item.Matched, ", "), "", strings.ReplaceAll(truncated(item.Text, 700), "\n", " "), "")
	}
	if err := os.WriteFile(filepath.Join(output, "latest.md"), []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		return err
	}
	return writeInbox(db, output)
}

func writeInbox(db *sql.DB, output string) error {
	if err := os.MkdirAll(output, 0o700); err != nil {
		return err
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM items WHERE reviewed=0`).Scan(&count); err != nil {
		return err
	}
	rows, err := db.Query(`SELECT id,source,title,url,author,published_at,text,score FROM items WHERE reviewed=0 ORDER BY score DESC,published_at DESC LIMIT 50`)
	if err != nil {
		return err
	}
	defer rows.Close()
	lines := []string{"# Threat research inbox", "", fmt.Sprintf("Unreviewed: %d. Showing the 50 highest scoring items.", count), ""}
	for rows.Next() {
		item, err := scanItem(rows)
		if err != nil {
			return err
		}
		lines = append(lines, fmt.Sprintf("## %d - %s", item.ID, strings.ReplaceAll(item.Title, "\n", " ")), "", fmt.Sprintf("%s - score %d - %s", item.Source, item.Score, item.PublishedAt), "", item.URL, "", strings.ReplaceAll(truncated(item.Text, 350), "\n", " "), "")
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(output, "inbox.md"), []byte(strings.Join(lines, "\n")), 0o600)
}

func allStates(db *sql.DB) ([]SourceState, error) {
	rows, err := db.Query(`SELECT source,cursor,last_success,last_error,partial FROM source_state ORDER BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	states := []SourceState{}
	for rows.Next() {
		var state SourceState
		if err := rows.Scan(&state.Source, &state.Cursor, &state.LastSuccess, &state.LastError, &state.Partial); err != nil {
			return nil, err
		}
		states = append(states, state)
	}
	return states, rows.Err()
}

func printStatus(db *sql.DB) error {
	states, err := allStates(db)
	if err != nil {
		return err
	}
	value := func(v *string) string {
		if v == nil || *v == "" {
			return "-"
		}
		return *v
	}
	for _, s := range states {
		fmt.Printf("%s: last_success=%s partial=%t cursor=%s error=%s\n", s.Source, value(s.LastSuccess), s.Partial != 0, value(s.Cursor), value(s.LastError))
	}
	return nil
}

func listItems(db *sql.DB, unread bool, search string, limit int) error {
	if limit < 1 {
		return fmt.Errorf("limit must be positive")
	}
	query := `SELECT id,source,title,url,author,published_at,text,score FROM items WHERE 1=1`
	args := []any{}
	if unread {
		query += ` AND reviewed=0`
	}
	if search != "" {
		query += ` AND (title LIKE ? OR text LIKE ?)`
		args = append(args, "%"+search+"%", "%"+search+"%")
	}
	query += ` ORDER BY score DESC,published_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := db.Query(query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		item, err := scanItem(rows)
		if err != nil {
			return err
		}
		fmt.Printf("%5d %2d %s %-26s %s\n", item.ID, item.Score, truncated(item.PublishedAt, 10), item.Source, truncated(item.Title, 100))
	}
	return rows.Err()
}

func showItem(db *sql.DB, id int64) error {
	var item Item
	err := db.QueryRow(`SELECT id,source,title,url,author,published_at,text,score FROM items WHERE id=?`, id).Scan(&item.ID, &item.Source, &item.Title, &item.URL, &item.Author, &item.PublishedAt, &item.Text, &item.Score)
	if err == sql.ErrNoRows {
		return fmt.Errorf("no such item %d", id)
	}
	if err != nil {
		return err
	}
	fmt.Printf("%s\n%s\n%s - %s - %s - score %d\n\n%s\n", item.Title, item.URL, item.Source, item.Author, item.PublishedAt, item.Score, item.Text)
	return nil
}

func writeBriefInput(db *sql.DB, output string, hours, limit int) (string, int, error) {
	cutoff := time.Now().UTC().Add(-time.Duration(hours) * time.Hour).Format("2006-01-02T15:04:05+00:00")
	rows, err := db.Query(`SELECT id,source,title,url,author,published_at,text,score FROM items WHERE published_at>=? ORDER BY published_at DESC LIMIT ?`, cutoff, limit)
	if err != nil {
		return "", 0, err
	}
	defer rows.Close()
	items := []Item{}
	for rows.Next() {
		item, err := scanItem(rows)
		if err != nil {
			return "", 0, err
		}
		item.Text = truncated(item.Text, 1600)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return "", 0, err
	}
	states, err := allStates(db)
	if err != nil {
		return "", 0, err
	}
	path := filepath.Join(output, "daily-input.json")
	payload := map[string]any{"generated_at": utcNow(), "window_hours": hours, "cutoff_utc": cutoff, "source_health": states, "items": items}
	return path, len(items), writeJSON(path, payload)
}

func importJSONL(db *sql.DB, path, source string, weights map[string]int) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	count, lineNo := 0, 0
	for scanner.Scan() {
		lineNo++
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var raw struct {
			ID          json.RawMessage `json:"id"`
			Text        string          `json:"text"`
			Title       string          `json:"title"`
			URL         string          `json:"url"`
			Author      string          `json:"author"`
			PublishedAt string          `json:"published_at"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &raw); err != nil {
			return count, fmt.Errorf("line %d: %w", lineNo, err)
		}
		id := strings.Trim(string(raw.ID), `"`)
		if id == "" || raw.Text == "" || raw.PublishedAt == "" {
			return count, fmt.Errorf("line %d: id, text, and published_at are required", lineNo)
		}
		title := raw.Title
		if title == "" {
			title = truncated(raw.Text, 120)
		}
		item := Item{Source: source, ExternalID: id, Title: title, URL: raw.URL, Author: raw.Author, PublishedAt: raw.PublishedAt, Text: raw.Text}
		change, err := saveItem(db, &item, weights)
		if err != nil {
			return count, fmt.Errorf("line %d: %w", lineNo, err)
		}
		if change != "unchanged" {
			count++
		}
	}
	return count, scanner.Err()
}
