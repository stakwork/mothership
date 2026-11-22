package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSwapHandler(t *testing.T) {
	h := &swapHandler{}
	serve := func() int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
		return rec.Code
	}
	if code := serve(); code != http.StatusServiceUnavailable {
		t.Fatalf("no handler yet: %d, want 503", code)
	}
	h.set(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }))
	if code := serve(); code != http.StatusAccepted {
		t.Fatalf("first handler: %d, want 202", code)
	}
	h.set(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	if code := serve(); code != http.StatusOK {
		t.Fatalf("after the swap: %d, want 200", code)
	}
}
