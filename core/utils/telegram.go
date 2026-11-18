package utils

// Telegram alerts (Batch 2).
//
// Sends attack start/end messages through a Telegram bot. The bot
// token and chat ID come only from the operator's config.json
// (per-domain "telegram" settings); nothing is invented, and the
// feature is inert when either value is missing. The token is used
// only in the request URL and is never logged: failures print a
// generic line with no error detail, because error strings can echo
// the request URL. Messages are plain text with no parse mode, so no
// escaping rules can break delivery.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sonushield/core/domains"
	"sonushield/core/pnc"
	"time"
)

func SendTelegram(domainData domains.DomainData, domainSettings domains.DomainSettings, notificationType int) {
	defer pnc.PanicHndl()

	telegram := domainSettings.DomainTelegram
	if telegram.BotToken == "" || telegram.ChatID == "" {
		return
	}

	template := telegram.AttackStartMsg
	if notificationType == 1 {
		template = telegram.AttackStopMsg
	}
	text := alertText(template, domainData, domainSettings.Name, notificationType)

	sendTelegramText(telegram, text)
}

// sendTelegramText posts one plain-text message. It is the
// shared transport for attack alerts and generic notices
// (utils.SendNotice); the token is used only in the request
// URL and is never logged.
func sendTelegramText(telegram domains.TelegramSettings, text string) {
	if telegram.BotToken == "" || telegram.ChatID == "" {
		return
	}

	payload, err := json.Marshal(map[string]string{
		"chat_id": telegram.ChatID,
		"text":    text,
	})
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", "https://api.telegram.org/bot"+telegram.BotToken+"/sendMessage", bytes.NewBuffer(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("[ ! ] [ Telegram alert failed ]")
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Println("[ ! ] [ Telegram alert failed ]")
	}
}
