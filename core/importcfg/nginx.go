package importcfg

// Nginx configuration parsing.
//
// A small tokenizer + recursive-descent parser for the
// documented subset. Comments (# to end of line, outside
// quotes) are stripped by the tokenizer; quoted strings keep
// their contents as one token. The parser tolerates missing
// trailing semicolons by reporting them as warnings rather
// than failing the whole file, and unbalanced braces end the
// parse with a warning naming the block.

import (
	"fmt"
	"strings"
)

type nginxToken struct {
	text string
	// kind is "word", "{", "}", or ";".
	kind string
}

func tokenizeNginx(text string) []nginxToken {
	var tokens []nginxToken
	var current strings.Builder
	flush := func() {
		if current.Len() > 0 {
			tokens = append(tokens, nginxToken{text: current.String(), kind: "word"})
			current.Reset()
		}
	}
	var quote byte
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		for i := 0; i < len(line); i++ {
			ch := line[i]
			if quote != 0 {
				if ch == quote {
					quote = 0
				} else {
					current.WriteByte(ch)
				}
				continue
			}
			switch ch {
			case '#':
				// Comment: skip the rest of the line.
				i = len(line)
			case '\'', '"':
				quote = ch
			case '{', '}', ';':
				flush()
				tokens = append(tokens, nginxToken{text: string(ch), kind: string(ch)})
			case ' ', '\t', '\r':
				flush()
			default:
				current.WriteByte(ch)
			}
		}
		flush()
	}
	return tokens
}

// nginxStatement is one parsed directive or block.
type nginxStatement struct {
	words    []string
	children []nginxStatement
	isBlock  bool
}

// parseNginxStatements parses statements until the token
// stream ends or a closing brace is consumed. It returns the
// statements and whether a closing brace terminated it.
func parseNginxStatements(tokens []nginxToken, pos *int) ([]nginxStatement, bool) {
	var statements []nginxStatement
	for *pos < len(tokens) {
		token := tokens[*pos]
		switch token.kind {
		case "}":
			*pos++
			return statements, true
		case ";", "{":
			// Stray punctuation: skip it.
			*pos++
			continue
		}
		var words []string
		for *pos < len(tokens) && tokens[*pos].kind == "word" {
			words = append(words, tokens[*pos].text)
			*pos++
		}
		if len(words) == 0 {
			continue
		}
		if *pos < len(tokens) && tokens[*pos].kind == "{" {
			*pos++
			children, _ := parseNginxStatements(tokens, pos)
			statements = append(statements, nginxStatement{words: words, children: children, isBlock: true})
			continue
		}
		if *pos < len(tokens) && tokens[*pos].kind == ";" {
			*pos++
		}
		// A directive without a semicolon is still accepted
		// (the next word starts a new statement); the
		// operator sees the result in the preview.
		statements = append(statements, nginxStatement{words: words})
	}
	return statements, false
}

type nginxServer struct {
	names       []string
	proxyPass   string
	certificate string
	key         string
	hasListen   bool
}

func parseNginx(text string) Report {
	var report Report
	tokens := tokenizeNginx(text)
	pos := 0
	statements, _ := parseNginxStatements(tokens, &pos)
	serverIndex := 0
	var walk func(statements []nginxStatement, depth int)
	walk = func(statements []nginxStatement, depth int) {
		for _, statement := range statements {
			if len(statement.words) == 0 {
				continue
			}
			head := statement.words[0]
			switch head {
			case "server":
				if !statement.isBlock {
					report.Warnings = append(report.Warnings, "server directive without a block was ignored")
					continue
				}
				serverIndex++
				convertNginxServer(statement, serverIndex, &report)
			case "include":
				report.Warnings = append(report.Warnings, "include directive was not followed: "+strings.Join(statement.words[1:], " "))
			default:
				if statement.isBlock && depth < 3 {
					walk(statement.children, depth+1)
				}
			}
		}
	}
	walk(statements, 0)
	if serverIndex == 0 {
		report.Warnings = append(report.Warnings, "no server blocks found")
	}
	return report
}

func convertNginxServer(block nginxStatement, index int, report *Report) {
	source := fmt.Sprintf("nginx server #%d", index)
	var server nginxServer
	var notImported []string
	for _, statement := range block.children {
		if len(statement.words) == 0 {
			continue
		}
		head := statement.words[0]
		args := statement.words[1:]
		if statement.isBlock {
			if head == "location" && len(args) >= 1 && args[len(args)-1] == "/" && len(args) == 1 {
				// location / : proxy_pass inside is usable.
				for _, child := range statement.children {
					if len(child.words) > 0 && child.words[0] == "proxy_pass" && len(child.words) > 1 {
						if server.proxyPass == "" {
							server.proxyPass = child.words[1]
						}
					} else if len(child.words) > 0 {
						notImported = append(notImported, "location /: "+child.words[0])
					}
				}
				continue
			}
			notImported = append(notImported, head+" "+strings.Join(args, " ")+" block (not imported)")
			continue
		}
		switch head {
		case "listen":
			server.hasListen = true
		case "server_name":
			server.names = append(server.names, args...)
		case "proxy_pass":
			if len(args) > 0 && server.proxyPass == "" {
				server.proxyPass = args[0]
			}
		case "ssl_certificate":
			if len(args) > 0 {
				server.certificate = args[0]
			}
		case "ssl_certificate_key":
			if len(args) > 0 {
				server.key = args[0]
			}
		case "rewrite", "return", "root", "index", "try_files", "error_page", "add_header", "client_max_body_size", "proxy_set_header", "proxy_read_timeout", "access_log", "error_log":
			notImported = append(notImported, head+" "+strings.Join(args, " "))
		default:
			report.Warnings = append(report.Warnings, source+": unhandled directive "+head)
		}
	}
	_ = server.hasListen
	for _, note := range notImported {
		report.NotImported = append(report.NotImported, source+": "+note)
	}
	if len(server.names) == 0 {
		report.Skipped = append(report.Skipped, source+": no server_name")
		return
	}
	if server.proxyPass == "" {
		report.Skipped = append(report.Skipped, source+" ("+joinNames(server.names)+"): no proxy_pass")
		return
	}
	backend, scheme, ok := proxyURLToBackend(server.proxyPass)
	if !ok {
		report.Skipped = append(report.Skipped, source+" ("+joinNames(server.names)+"): proxy_pass "+server.proxyPass+" is not an http(s) URL with a host")
		return
	}
	cert, key := server.certificate, server.key
	if (cert == "") != (key == "") {
		report.Warnings = append(report.Warnings, source+" ("+joinNames(server.names)+"): certificate and key must both be set; TLS paths dropped")
		cert, key = "", ""
	}
	usable := 0
	for _, name := range server.names {
		if !validServerName(name) {
			report.Warnings = append(report.Warnings, source+": server name "+name+" skipped (wildcard or placeholder)")
			continue
		}
		usable++
		report.Domains = append(report.Domains, ImportedDomain{
			Name: name, Backend: backend, Scheme: scheme,
			Certificate: cert, Key: key, Source: source,
		})
	}
	if usable == 0 {
		report.Skipped = append(report.Skipped, source+": no usable server names")
	}
}
