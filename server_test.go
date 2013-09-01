// Copyright 2013 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// Server configuration.
var (
	addrs = []string{
		"127.0.0.1:44380",
		"127.0.0.1:44381",
	}
	serverName = "localhost"
	certFile   = "./test/snakeoil_test.crt"
	keyFile    = "./test/snakeoil_test.key"
)

// Client configuration.
var (
	httpTransport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Since we're using snakeoil certs for testing
		},
	}
	httpClient = &http.Client{
		Transport: httpTransport,
	}
)

// Route configuration.
var (
	simpleRoute      = "/simple"
	longRunningRoute = "/long"
)

func init() {
	ServeMux.HandleFunc(simpleRoute, simpleHandler)
	ServeMux.HandleFunc(longRunningRoute, longRunningHandler)
}

func TestBasicOperation(t *testing.T) {
	if err := HTTPS(addrs, serverName, certFile, keyFile, nil); err != nil {
		t.Fatalf("Expected no error starting server, received '%v'.", err)
	}
	defer Shutdown()

	// Requests to a running server should succeed.
	for _, addr := range addrs {
		if err := makeRequest(addr, simpleRoute, true); err != nil {
			t.Fatalf("Request failed: '%v'.", err)
		}
	}

	// Each listener should have a unique TLS session ticket key.
	if activeListeners.listeners[0].tlsConfig.SessionTicketKey == activeListeners.listeners[1].tlsConfig.SessionTicketKey {
		t.Error("Expected session ticket keys to not match.")
	}

	Shutdown()

	// There should be not active listeners after shutting down.
	if len(activeListeners.listeners) != 0 {
		t.Errorf("Expected no active listeners, received '%v'.", len(activeListeners.listeners))
	}

	// Requests to a non-running server should fail.
	for _, addr := range addrs {
		if err := makeRequest(addr, simpleRoute, false); err != nil {
			t.Errorf("Request failed: '%v'.", err)
		}
	}
}

func TestGracefulShutdown(t *testing.T) {
	// FIXME: I can very easily manually test this, but I can't for the life
	// of me find a way to successfully test it here.
}

func TestReuseListeners(t *testing.T) {
	if err := HTTPS(addrs, serverName, certFile, keyFile, nil); err != nil {
		t.Fatalf("Expected no error starting server, received '%v'.", err)
	}
	defer Shutdown()

	// Requests to a running server should succeed.
	for _, addr := range addrs {
		if err := makeRequest(addr, simpleRoute, true); err != nil {
			t.Fatalf("Request failed: '%v'.", err)
		}
	}

	// Store the current TLS session ticket keys.
	tlsSessionTicketKeys := make(map[string][32]byte)
	for _, li := range activeListeners.listeners {
		tlsSessionTicketKeys[li.Addr().String()] = li.tlsConfig.SessionTicketKey
	}

	existingListeners, err := Detach()
	if err != nil {
		t.Fatalf("Expected no error detaching listeners, received '%v'.", err)
	}

	// The server should reuse the existing listeners.
	if err := HTTPS(addrs, serverName, certFile, keyFile, existingListeners); err != nil {
		t.Fatalf("Expected no error starting server, received '%v'.", err)
	}

	// Requests to a running server should succeed.
	for _, addr := range addrs {
		if err := makeRequest(addr, simpleRoute, true); err != nil {
			t.Fatalf("Request failed: '%v'.", err)
		}
	}

	// Verify that the TLS session ticket keys haven't changed.
	for _, li := range activeListeners.listeners {
		expectedKey, exists := tlsSessionTicketKeys[li.Addr().String()]
		if !exists {
			t.Errorf("Expected a session ticket key for %v to exist.", li.Addr().String())
		} else if expectedKey != li.tlsConfig.SessionTicketKey {
			t.Errorf("Expected session ticket keys for %v to match.", li.Addr().String())
		}
	}
}

func makeRequest(addr string, route string, expectSuccess bool) error {
	url := "https://" + addr + route
	resp, err := httpClient.Get(url)
	if expectSuccess {
		if err != nil {
			return fmt.Errorf("Expected no error connecting to %v, received '%v'.", url, err)
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("Expected response code 200 from %v, received '%v'.", url, resp.StatusCode)
		}
	} else {
		if err == nil {
			return fmt.Errorf("Expected failure connecting to %v.", url)
		}
	}
	return nil
}

func simpleHandler(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintln(w, "Success")
}

func longRunningHandler(w http.ResponseWriter, req *http.Request) {
	time.Sleep(2 * time.Second)
	fmt.Fprintln(w, "Success")
}
