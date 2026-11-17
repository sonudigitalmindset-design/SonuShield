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

func checkWaitingRoom(writer http.ResponseWriter, request *http.Request, ip string, room *domains.WaitingRoom, bypassedRPS int) bool {
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
	fmt.Fprintf(writer, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="5"><meta name="robots" content="noindex"><title>Please wait</title><style>body{font-family:Arial,sans-serif;background:#f5f5f5;color:#333;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}.box{background:#fff;border:1px solid #ddd;border-radius:4px;padding:32px;max-width:420px;text-align:center}h1{font-size:20px;margin:0 0 8px}p{margin:8px 0;color:#666}.pos{font-size:36px;font-weight:bold;color:#111;margin:16px 0}</style></head><body><div class="box"><h1>Please wait</h1><p>This site is busy right now. You are in line and this page will refresh automatically.</p><div class="pos">Position %d</div><p>Please do not refresh manually — your place in line is kept automatically.</p></div></body></html>`, decision.Position)
	return true
}
