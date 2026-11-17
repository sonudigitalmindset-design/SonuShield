package utils

// Email alerts (Batch 2).
//
// Sends attack start/end messages over SMTP. All settings come only
// from the operator's config.json (per-domain "email" settings); the
// feature is inert when the SMTP host or the recipient is missing.
// Credentials are used only for SMTP authentication and are never
// logged: failures print a generic line with no error detail.
//
// Transport: plain TCP with opportunistic STARTTLS by default
// (upgraded whenever the server advertises it), or implicit TLS
// when "useTLS" is set (the usual port-465 setup). Authentication
// uses PLAIN auth only when a username is configured; Go's PLAIN
// implementation refuses to send credentials over an unencrypted
// connection to a remote host, so a server without TLS cannot
// receive the password. Header values from config are stripped of
// CR/LF to prevent header injection.

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"sonushield/core/domains"
	"sonushield/core/pnc"
	"strconv"
	"strings"
	"time"
)

func SendEmail(domainData domains.DomainData, domainSettings domains.DomainSettings, notificationType int) {
	defer pnc.PanicHndl()

	email := domainSettings.DomainEmail
	if email.SMTPHost == "" || email.To == "" {
		return
	}

	port := email.SMTPPort
	if port <= 0 {
		port = 587
	}
	address := net.JoinHostPort(email.SMTPHost, strconv.Itoa(port))

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	var err error
	if email.UseTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", address, &tls.Config{ServerName: email.SMTPHost})
	} else {
		conn, err = dialer.Dial("tcp", address)
	}
	if err != nil {
		fmt.Println("[ ! ] [ Email alert failed ]")
		return
	}

	client, err := smtp.NewClient(conn, email.SMTPHost)
	if err != nil {
		conn.Close()
		fmt.Println("[ ! ] [ Email alert failed ]")
		return
	}
	defer client.Close()

	if !email.UseTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: email.SMTPHost}); err != nil {
				fmt.Println("[ ! ] [ Email alert failed ]")
				return
			}
		}
	}

	if email.Username != "" {
		auth := smtp.PlainAuth("", email.Username, email.Password, email.SMTPHost)
		if err := client.Auth(auth); err != nil {
			fmt.Println("[ ! ] [ Email alert failed ]")
			return
		}
	}

	from := email.From
	if from == "" {
		from = email.Username
	}
	from = stripHeaderNewlines(from)
	to := stripHeaderNewlines(email.To)

	subject := "SonuShield DDoS alert: " + domainSettings.Name + " — attack started"
	template := email.AttackStartMsg
	if notificationType == 1 {
		subject = "SonuShield DDoS alert: " + domainSettings.Name + " — attack stopped"
		template = email.AttackStopMsg
	}
	subject = stripHeaderNewlines(subject)
	body := alertText(template, domainData, domainSettings.Name, notificationType)

	if err := client.Mail(from); err != nil {
		fmt.Println("[ ! ] [ Email alert failed ]")
		return
	}
	if err := client.Rcpt(to); err != nil {
		fmt.Println("[ ! ] [ Email alert failed ]")
		return
	}
	writer, err := client.Data()
	if err != nil {
		fmt.Println("[ ! ] [ Email alert failed ]")
		return
	}
	message := "From: " + from + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"\r\n" + body + "\r\n"
	if _, err := writer.Write([]byte(message)); err != nil {
		writer.Close()
		fmt.Println("[ ! ] [ Email alert failed ]")
		return
	}
	if err := writer.Close(); err != nil {
		fmt.Println("[ ! ] [ Email alert failed ]")
		return
	}
	client.Quit()
}

func stripHeaderNewlines(value string) string {
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", "")
	return value
}
