package server

// Waiting-room request handling (Batch 4).
//
// checkWaitingRoom evaluates one request against the domain's
// waiting room. It returns true when the request was fully
// handled here (waiting page or queue-full response) and the
// middleware must not continue to the backend.
//
// The waiting page is deliberately generic and unbranded: no
// product name, no marketing, just the queue position and an
// automatic refresh. It is only ever shown to excess visitors
// while the domain is over its threshold.

import (
	"fmt"
	"net/http"
	"sonushield/core/domains"
)

func checkWaitingRoom(writer http.ResponseWriter, request *http.Request, ip string, room *domains.WaitingRoom, bypassedRPS int, template string) bool {
	decision := room.Evaluate(request, ip, bypassedRPS)
	if decision.Pass {
		if decision.AdmittedCookie != nil {
			http.SetCookie(writer, decision.AdmittedCookie)
		}
		return false
	}

	if decision.Full {
		writer.Header().Set("Content-Type", "text/plain")
		writer.Header().Set("Retry-After", "10")
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(writer, "The site is very busy right now. Please try again shortly.")
		return true
	}

	if decision.QueueCookie != nil {
		http.SetCookie(writer, decision.QueueCookie)
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	writer.WriteHeader(http.StatusOK)
	//Built-in page text is English/Hindi by Accept-Language; a
	//validated custom template replaces the visible part.
	pageStr := stringsFor(request)
	if template != "" {
		fmt.Fprint(writer, renderWaitingTemplate(template, pageStr, decision.Position))
	} else {
		fmt.Fprint(writer, waitingPage(pageStr, decision.Position))
	}
	return true
}
