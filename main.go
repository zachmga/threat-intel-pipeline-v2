package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Database      string         `json:"database"`
	OutputDir     string         `json:"output_dir"`
	Sources       []Source       `json:"sources"`
	PriorityTerms map[string]int `json:"priority_terms"`
}

type SourceResult struct {
	Source  string `json:"source"`
	Status  string `json:"status"`
	Changes int    `json:"changes"`
	Error   string `json:"error,omitempty"`
}

func readConfig(path string) (Config, string, error) {
	var config Config
	data, err := os.ReadFile(path)
	if err != nil {
		return config, "", err
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return config, "", err
	}
	if config.Database == "" {
		config.Database = "data/intel.sqlite3"
	}
	if config.OutputDir == "" {
		config.OutputDir = "output"
	}
	if config.PriorityTerms == nil {
		config.PriorityTerms = map[string]int{}
	}
	if len(config.Sources) == 0 {
		return config, "", fmt.Errorf("config has no sources")
	}
	for _, s := range config.Sources {
		if s.Name == "" || s.Kind == "" {
			return config, "", fmt.Errorf("every source needs name and kind")
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return config, "", err
	}
	return config, filepath.Dir(abs), nil
}

func (c *Collector) collect(source Source, emit func(Item) error) (bool, string, error) {
	switch source.Kind {
	case "discourse":
		return c.discourse(source, emit)
	case "feed", "onion_feed":
		return c.feed(source, emit)
	case "x_recent":
		return c.xRecent(source, emit)
	case "mastodon_public":
		return c.mastodonPublic(source, emit)
	case "onion_html":
		return c.onionHTML(source, emit)
	default:
		return false, "", fmt.Errorf("unsupported source kind %q", source.Kind)
	}
}

func shouldPoll(state SourceState, intervalMinutes int) bool {
	if intervalMinutes <= 0 || state.LastSuccess == nil {
		return true
	}
	t, err := time.Parse(time.RFC3339, *state.LastSuccess)
	if err != nil {
		return true
	}
	return time.Since(t) >= time.Duration(intervalMinutes)*time.Minute
}

func (c *Collector) run(sources []Source, bootstrap bool) ([]Item, []SourceResult) {
	changes := []Item{}
	results := []SourceResult{}
	for _, source := range sources {
		if !source.isEnabled() {
			continue
		}
		state, err := readSourceState(c.DB, source.Name)
		if err != nil {
			results = append(results, SourceResult{Source: source.Name, Status: "error", Error: err.Error()})
			continue
		}
		if !shouldPoll(state, source.MinIntervalMinutes) {
			results = append(results, SourceResult{Source: source.Name, Status: "skipped"})
			continue
		}
		before := len(changes)
		emit := func(item Item) error {
			change, err := saveItem(c.DB, &item, c.Weights)
			if err != nil {
				return err
			}
			if change != "unchanged" && !bootstrap {
				item.Change = change
				changes = append(changes, item)
			}
			return nil
		}
		partial, cursor, err := c.collect(source, emit)
		if err != nil {
			_ = writeSourceState(c.DB, source.Name, "", err.Error(), false)
			status := "error"
			if strings.Contains(err.Error(), "token missing") || strings.Contains(err.Error(), "Tor proxy") {
				status = "needs_setup"
			}
			results = append(results, SourceResult{Source: source.Name, Status: status, Changes: len(changes) - before, Error: err.Error()})
			continue
		}
		if partial && !source.Sampled {
			cursor = ""
		}
		if err := writeSourceState(c.DB, source.Name, cursor, "", partial); err != nil {
			results = append(results, SourceResult{Source: source.Name, Status: "error", Changes: len(changes) - before, Error: err.Error()})
			continue
		}
		status := "ok"
		if partial {
			status = "partial"
			if source.Sampled {
				status = "sampled"
			}
		}
		results = append(results, SourceResult{Source: source.Name, Status: status, Changes: len(changes) - before})
	}
	return changes, results
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: intel [-config path] <run|status|list|show|mark|brief-input|import-jsonl> [options]")
	fmt.Fprintln(os.Stderr, "  run --bootstrap                 Seed existing posts without marking them new")
	fmt.Fprintln(os.Stderr, "  list --unread --search term     Review stored posts")
	fmt.Fprintln(os.Stderr, "  show ID | mark ID --reviewed    Inspect or review one post")
	fmt.Fprintln(os.Stderr, "  brief-input --hours 24          Export source material for an analyst brief")
	fmt.Fprintln(os.Stderr, "  import-jsonl FILE --source NAME Import an authorized local export")
}

func cli(args []string) error {
	global := flag.NewFlagSet("intel", flag.ContinueOnError)
	configPath := global.String("config", "config.json", "configuration path")
	if err := global.Parse(args); err != nil {
		return err
	}
	rest := global.Args()
	if len(rest) == 0 {
		usage()
		return fmt.Errorf("missing command")
	}
	command := rest[0]
	commandArgs := rest[1:]
	config, root, err := readConfig(*configPath)
	if err != nil {
		return err
	}
	db, err := openStore(filepath.Join(root, config.Database))
	if err != nil {
		return err
	}
	defer db.Close()
	output := filepath.Join(root, config.OutputDir)
	c := newCollector(db, config.PriorityTerms, root)
	switch command {
	case "run":
		flags := flag.NewFlagSet("run", flag.ContinueOnError)
		bootstrap := flags.Bool("bootstrap", false, "seed existing posts")
		if err := flags.Parse(commandArgs); err != nil {
			return err
		}
		changes, results := c.run(config.Sources, *bootstrap)
		if err := writeDigest(db, output, changes, results); err != nil {
			return err
		}
		failed := false
		for _, r := range results {
			fmt.Printf("%s: %s (%d changes)", r.Source, r.Status, r.Changes)
			if r.Error != "" {
				fmt.Printf(" - %s", r.Error)
			}
			fmt.Println()
			if r.Status == "error" || r.Status == "partial" {
				failed = true
			}
		}
		fmt.Println("Digest:", filepath.Join(output, "latest.md"))
		if failed {
			return errors.New("one or more sources failed or were partial")
		}
	case "status":
		return printStatus(db)
	case "list":
		flags := flag.NewFlagSet("list", flag.ContinueOnError)
		unread := flags.Bool("unread", false, "only unreviewed items")
		search := flags.String("search", "", "text search")
		limit := flags.Int("limit", 30, "maximum rows")
		if err := flags.Parse(commandArgs); err != nil {
			return err
		}
		return listItems(db, *unread, *search, *limit)
	case "show":
		if len(commandArgs) != 1 {
			return fmt.Errorf("show requires an item ID")
		}
		id, err := strconv.ParseInt(commandArgs[0], 10, 64)
		if err != nil {
			return err
		}
		return showItem(db, id)
	case "mark":
		if len(commandArgs) < 2 {
			return fmt.Errorf("mark requires an item ID and --reviewed or --unread")
		}
		id, err := strconv.ParseInt(commandArgs[0], 10, 64)
		if err != nil {
			return err
		}
		flags := flag.NewFlagSet("mark", flag.ContinueOnError)
		reviewed := flags.Bool("reviewed", false, "mark reviewed")
		unread := flags.Bool("unread", false, "mark unread")
		if err := flags.Parse(commandArgs[1:]); err != nil {
			return err
		}
		if *reviewed == *unread {
			return fmt.Errorf("choose exactly one of --reviewed or --unread")
		}
		res, err := db.Exec(`UPDATE items SET reviewed=? WHERE id=?`, boolInt(*reviewed), id)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return fmt.Errorf("no such item %d", id)
		}
		return writeInbox(db, output)
	case "brief-input":
		flags := flag.NewFlagSet("brief-input", flag.ContinueOnError)
		hours := flags.Int("hours", 24, "lookback hours")
		limit := flags.Int("limit", 100, "maximum items")
		if err := flags.Parse(commandArgs); err != nil {
			return err
		}
		if *hours < 1 || *limit < 1 {
			return fmt.Errorf("hours and limit must be positive")
		}
		path, count, err := writeBriefInput(db, output, *hours, *limit)
		if err == nil {
			fmt.Printf("%d recent items written to %s\n", count, path)
		}
		return err
	case "import-jsonl":
		if len(commandArgs) < 1 {
			return fmt.Errorf("import-jsonl requires a file")
		}
		flags := flag.NewFlagSet("import-jsonl", flag.ContinueOnError)
		source := flags.String("source", "", "source name")
		if err := flags.Parse(commandArgs[1:]); err != nil {
			return err
		}
		if *source == "" {
			return fmt.Errorf("--source is required")
		}
		count, err := importJSONL(db, commandArgs[0], *source, config.PriorityTerms)
		if err != nil {
			return err
		}
		fmt.Printf("Imported %d new or updated items\n", count)
		return writeInbox(db, output)
	default:
		usage()
		return fmt.Errorf("unknown command %q", command)
	}
	return nil
}

func main() {
	if err := cli(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
