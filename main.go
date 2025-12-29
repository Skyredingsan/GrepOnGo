package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type GrepOptions struct {
	Pattern        string
	Files          []string
	IgnoreCase     bool
	ShowLineNumber bool
	CountOnly      bool
	InvertMatch    bool

	UseRegexp bool

	Before  int
	After   int
	Context int

	Highlight bool
}

type resultLine struct {
	file       string
	lineNumber int
	text       string
	matched    bool
}

func GrepStream(r io.Reader, fileName string, opts GrepOptions, out chan<- resultLine) error {
	var re *regexp.Regexp
	var err error

	useRe := opts.UseRegexp
	pat := opts.Pattern

	if pat == "" {
		return fmt.Errorf("Паттерн пустой")
	}

	if opts.IgnoreCase && !useRe {
		pat = strings.ToLower(pat)
	}

	if useRe {
		flags := ""
		if opts.IgnoreCase {
			flags = "(?i)"
		}
		re, err = regexp.Compile(flags + opts.Pattern)
		if err != nil {
			return fmt.Errorf("Ошибка regexp: %w", err)
		}
	}

	if opts.Context > 0 {
		opts.Before = opts.Context
		opts.After = opts.Context
	}

	scanner := bufio.NewScanner(r)
	lineNumber := 0

	type beforeItem struct {
		num  int
		text string
	}

	beforeBuf := make([]beforeItem, 0, opts.Before)
	afterLeft := 0
	lastPrintedNumber := -1
	firstOutputDone := false

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()

		lineToCheck := line
		if opts.IgnoreCase && !useRe {
			lineToCheck = strings.ToLower(lineToCheck)
		}
		var matched bool
		if useRe {
			matched = re.MatchString(lineToCheck)
		} else {
			matched = strings.Contains(lineToCheck, pat)
		}
		if opts.InvertMatch {
			matched = !matched
		}

		if opts.Before > 0 {
			if len(beforeBuf) == opts.Before {
				beforeBuf = append(beforeBuf[1:], beforeItem{num: lineNumber, text: line})
			} else {
				beforeBuf = append(beforeBuf, beforeItem{num: lineNumber, text: line})
			}
		} else {
			if len(beforeBuf) > 0 {
				beforeBuf = beforeBuf[:0]
			}
		}

		if matched {
			if firstOutputDone && lastPrintedNumber > 0 && (lineNumber-lastPrintedNumber) > (opts.After+opts.Before+1) {
				out <- resultLine{file: fileName, lineNumber: -1, text: "--", matched: false}
			}
			startIdx := 0
			if len(beforeBuf) > 0 {
				for i, it := range beforeBuf {
					if it.num >= lineNumber {
						startIdx = i + 1
					}
				}
				for i := startIdx; i < len(beforeBuf); i++ {
					it := beforeBuf[i]
					out <- resultLine{file: fileName, lineNumber: it.num, text: it.text, matched: false}
				}
			}

			out <- resultLine{file: fileName, lineNumber: lineNumber, text: line, matched: true}
			firstOutputDone = true
			lastPrintedNumber = lineNumber
			afterLeft = opts.After
			continue
		}

		if afterLeft > 0 {
			out <- resultLine{file: fileName, lineNumber: lineNumber, text: line, matched: false}
			lastPrintedNumber = lineNumber
			afterLeft--
			firstOutputDone = true
			continue
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("Ошибка чтения: %w", err)
	}
	return nil
}

func GrepFiles(opts GrepOptions) ([]string, error) {

	outCh := make(chan resultLine)
	errCh := make(chan error, 1)

	go func() {
		defer close(outCh)
		for _, fpath := range opts.Files {

			if fpath == "-" {
				if err := GrepStream(os.Stdin, "(stdin)", opts, outCh); err != nil {
					errCh <- err
					return
				}
				continue
			}
			fp, err := os.Open(fpath)
			if err != nil {
				errCh <- fmt.Errorf("Открытие %s: %w", fpath, err)
				return
			}
			err = GrepStream(fp, fpath, opts, outCh)
			fp.Close()
			if err != nil {
				errCh <- err
				return
			}
		}
		errCh <- nil
	}()

	results := make([]string, 0)
	count := 0

	for rl := range outCh {
		if rl.lineNumber == -1 && rl.text == "--" {
			results = append(results, rl.text)
			continue
		}
		if opts.CountOnly {
			count++
			continue
		}
		display := rl.text

		if opts.Highlight && rl.matched {
			if opts.UseRegexp {
				flags := ""
				if opts.IgnoreCase {
					flags = "(?i)"
				}
				re, err := regexp.Compile(flags + opts.Pattern)
				if err == nil {
					display = re.ReplaceAllStringFunc(display, func(m string) string {
						return "\x1b[43m" + m + "\x1b[0m"
					})
				}
			} else {
				search := opts.Pattern
				if opts.IgnoreCase {
					lower := strings.ToLower(display)
					searchLower := strings.ToLower(search)
					var b strings.Builder
					idx := 0
					for {
						pos := strings.Index(lower[idx:], searchLower)
						if pos == -1 {
							b.WriteString(display[idx:])
							break
						}
						pos += idx
						b.WriteString(display[idx:pos])
						b.WriteString("\x1b[43m")
						b.WriteString(display[pos : pos+len(search)])
						b.WriteString("\x1b[0m")
						idx = pos + len(search)
					}
					display = b.String()
				} else {
					var b strings.Builder
					idx := 0
					for {
						pos := strings.Index(display[idx:], search)
						if pos == -1 {
							b.WriteString(display[idx:])
							break
						}
						pos += idx
						b.WriteString(display[idx:pos])
						b.WriteString("\x1b[43m")
						b.WriteString(display[pos : pos+len(search)])
						b.WriteString("\x1b[0m")
						idx = pos + len(search)
					}
					display = b.String()
				}
			}
		}
		prefix := ""
		if len(opts.Files) > 1 {
			prefix = filepath.Base(rl.file) + ":"
		}
		if opts.ShowLineNumber {
			prefix += fmt.Sprintf("%d", rl.lineNumber)
		}
		results = append(results, prefix+display)
	}
	if err := <-errCh; err != nil {
		return nil, err
	}

	if opts.CountOnly {
		return []string{fmt.Sprintf("%d", count)}, nil
	}
	return results, nil
}

func main() {
	var optPattern = flag.String("e", "", "pattern (required)")
	var optFiles = flag.String("f", "", "comma-separated files (if empty read stdin)")
	var optIgnore = flag.Bool("i", false, "ignore case")
	var optLineNum = flag.Bool("n", false, "show line numbers")
	var optCount = flag.Bool("c", false, "count only")
	var optInvert = flag.Bool("v", false, "invert match")
	var optRegexp = flag.Bool("r", false, "use regexp")
	var optBefore = flag.Int("B", 0, "lines before")
	var optAfter = flag.Int("A", 0, "lines after")
	var optContext = flag.Int("C", 0, "lines of context (sets both before and after)")
	var optHighlight = flag.Bool("H", false, "highlight matches (ANSI)")

	flag.Parse()

	if *optPattern == "" {
		fmt.Fprintln(os.Stderr, "pattern required (-e)")
		os.Exit(2)
	}

	files := []string{}
	if *optFiles != "" {
		for _, p := range strings.Split(*optFiles, ",") {
			files = append(files, strings.TrimSpace(p))
		}
	} else {
		files = []string{"-"}
	}

	opts := GrepOptions{
		Pattern:        *optPattern,
		Files:          files,
		IgnoreCase:     *optIgnore,
		ShowLineNumber: *optLineNum,
		CountOnly:      *optCount,
		InvertMatch:    *optInvert,
		UseRegexp:      *optRegexp,
		Before:         *optBefore,
		After:          *optAfter,
		Context:        *optContext,
		Highlight:      *optHighlight,
	}

	res, err := GrepFiles(opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	for _, line := range res {
		fmt.Println(line)
	}
}
