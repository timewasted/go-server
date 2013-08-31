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
	if err := ListenAndServeTLS(addrs, serverName, certFile, keyFile); err != nil {
		t.Fatalf("Failed to start server: '%v'.", err)
	}
	defer Shutdown()

	// Ensure that the server started.
	for _, addr := range addrs {
		if err := makeRequest(addr, simpleRoute, true); err != nil {
			t.Fatalf("Server startup failed: '%v'.", err)
		}
	}

	Shutdown()

	// Ensure that the server shut down.
	for _, addr := range addrs {
		if err := makeRequest(addr, simpleRoute, false); err != nil {
			t.Errorf("Server shutdown failed: '%v'.", err)
		}
	}
}

func TestGracefulShutdown(t *testing.T) {
	// FIXME: I can very easily manually test this, but I can't for the life
	// of me find a way to successfully test it here.
}

func makeRequest(addr string, route string, expectSuccess bool) error {
	resp, err := httpClient.Get("https://" + addr + route)
	if expectSuccess {
		if err != nil {
			return fmt.Errorf("Failed to connect to https://%v%v: '%v'.", addr, route, err)
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("Expected response code 200 from https://%v%v, received '%v'.", addr, route, resp.StatusCode)
		}
	} else {
		if err == nil {
			return fmt.Errorf("Successfully connected to https://%v%v while expecting failure.", addr, route)
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
