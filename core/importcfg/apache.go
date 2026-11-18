package importcfg

// Apache configuration parsing.
//
// Line-oriented: VirtualHost containers are tracked by
// depth, directives inside them are split on whitespace
// (quoted values keep their contents), and comment lines and
// trailing comments are stripped. Directives outside any
// VirtualHost are server-global and are ignored — only
// VirtualHost blocks are read, which the report notes when
// no vhost is found. Location/Directory containers inside a
// vhost are reported as not imported; their contents are
// skipped as a unit.

import (
	"fmt"
	"strings"
)

func stripApacheComment(line string) string {
	var quote byte
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if quote != 0 {
			if ch == quote {
				quote = 0
			}
			continue
		}
		switch ch {
		case '\'', '"':
			quote = ch
		case '#':
			if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' {
				return line[:i]
			}
		}
	}
	return line
}

func splitApacheFields(line string) []string {
	var fields []string
	var current strings.Builder
	var quote byte
	flush := func() {
		if current.Len() > 0 {
			fields = append(fields, current.String())
			current.Reset()
		}
	}
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
		case '\'', '"':
			quote = ch
		case ' ', '\t':
			flush()
		default:
			current.WriteByte(ch)
		}
	}
	flush()
	return fields
}

type apacheVhost struct {
	names       []string
	proxyPass   string
	certificate string
	key         string
}

func parseApache(text string) Report {
	var report Report
	vhostIndex := 0
	var current *apacheVhost
	var currentSource string
	var notImported []string
	// containerDepth tracks nested containers inside a vhost
	// (Location, Directory, ...): their contents are skipped
	// and the container itself is reported once.
	containerDepth := 0
	containerName := ""
	flush := func() {
		if current == nil {
			return
		}
		convertApacheVhost(current, currentSource, notImported, &report)
		current = nil
		notImported = nil
	}
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(stripApacheComment(rawLine))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "<") {
			tag := strings.Trim(line, "<>")
			closing := strings.HasPrefix(tag, "/")
			tagName := strings.ToLower(strings.Fields(strings.TrimPrefix(tag, "/"))[0])
			if tagName == "virtualhost" {
				if closing {
					flush()
				} else {
					flush()
					vhostIndex++
					current = &apacheVhost{}
					currentSource = fmt.Sprintf("apache vhost #%d", vhostIndex)
					containerDepth = 0
				}
				continue
			}
			if current != nil {
				if closing {
					if containerDepth > 0 {
						containerDepth--
					}
				} else {
					if containerDepth == 0 {
						containerName = tag
						notImported = append(notImported, "<"+tag+"> block (not imported)")
					}
					containerDepth++
				}
			}
			continue
		}
		if current == nil || containerDepth > 0 {
			continue
		}
		fields := splitApacheFields(line)
		if len(fields) == 0 {
			continue
		}
		head := fields[0]
		args := fields[1:]
		switch head {
		case "ServerName":
			if len(args) > 0 {
				current.names = append(current.names, args[0])
			}
		case "ServerAlias":
			current.names = append(current.names, args...)
		case "ProxyPass":
			// ProxyPass <path> <url> [options]. Only "/" is used.
			if len(args) >= 2 && args[0] == "/" && current.proxyPass == "" {
				current.proxyPass = args[1]
			} else if len(args) >= 2 {
				notImported = append(notImported, "ProxyPass "+args[0]+" (only \"/\" is imported)")
			}
		case "SSLCertificateFile":
			if len(args) > 0 {
				current.certificate = args[0]
			}
		case "SSLCertificateKeyFile":
			if len(args) > 0 {
				current.key = args[0]
			}
		case "RewriteRule", "RewriteEngine", "RewriteCond", "Redirect", "RedirectMatch", "DocumentRoot", "DirectoryIndex", "ErrorLog", "CustomLog", "ProxyPassReverse", "ProxyPreserveHost", "Header", "SSLEngine":
			notImported = append(notImported, head+" "+strings.Join(args, " "))
		case "Include", "IncludeOptional":
			report.Warnings = append(report.Warnings, currentSource+": include directive was not followed: "+strings.Join(args, " "))
		default:
			report.Warnings = append(report.Warnings, currentSource+": unhandled directive "+head)
		}
	}
	_ = containerName
	flush()
	if vhostIndex == 0 {
		report.Warnings = append(report.Warnings, "no VirtualHost blocks found")
	}
	return report
}

func convertApacheVhost(vhost *apacheVhost, source string, notImported []string, report *Report) {
	for _, note := range notImported {
		report.NotImported = append(report.NotImported, source+": "+note)
	}
	if len(vhost.names) == 0 {
		report.Skipped = append(report.Skipped, source+": no ServerName")
		return
	}
	if vhost.proxyPass == "" {
		report.Skipped = append(report.Skipped, source+" ("+joinNames(vhost.names)+"): no ProxyPass for \"/\"")
		return
	}
	backend, scheme, ok := proxyURLToBackend(vhost.proxyPass)
	if !ok {
		report.Skipped = append(report.Skipped, source+" ("+joinNames(vhost.names)+"): ProxyPass "+vhost.proxyPass+" is not an http(s) URL with a host")
		return
	}
	cert, key := vhost.certificate, vhost.key
	if (cert == "") != (key == "") {
		report.Warnings = append(report.Warnings, source+" ("+joinNames(vhost.names)+"): certificate and key must both be set; TLS paths dropped")
		cert, key = "", ""
	}
	usable := 0
	for _, name := range vhost.names {
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
