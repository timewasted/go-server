// Copyright 2013 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
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
	keyPairs = map[string]string{
		"./test/srv1.localhost.crt": "./test/srv1.localhost.key",
		"./test/srv2.localhost.crt": "./test/srv2.localhost.key",
	}
	addrToServerName = map[string]string{
		addrs[0]: "srv1.localhost",
		addrs[1]: "srv2.localhost",
	}
)

// Client configuration.
var (
	caCertFile    = "./test/GoTestingCA.crt"
	httpTransport = &http.Transport{
		TLSClientConfig: &tls.Config{},
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
	// Trust the provided CA cert.
	caCert, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		panic("Failed to read CA cert file.")
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caCert) {
		panic("Failed to add CA cert to pool.")
	}
	httpTransport.TLSClientConfig.RootCAs = rootCAs

	ServeMux.HandleFunc(simpleRoute, simpleHandler)
	ServeMux.HandleFunc(longRunningRoute, longRunningHandler)
}

func TestBasicOperation(t *testing.T) {
	if err := HTTPS(addrs, keyPairs, nil); err != nil {
		t.Fatalf("Expected no error when starting server, received '%v'.", err)
	}
	defer Shutdown()
	Serve()

	// Ensure that the server is accepting connections.
	for addr, serverName := range addrToServerName {
		if err := requestSuccess(addr, serverName, simpleRoute); err != nil {
			t.Fatal(err)
		}
	}

	// Ensure that SNI is working.
	if err := requestFailure(addrToServerName[addrs[0]], "invalid.example.com", simpleRoute); err != nil {
		t.Fatal(err)
	}

	// Ensure that each listener has a unique TLS session ticket key.
	if managedListeners.listeners[0].tlsConfig.SessionTicketKey ==
		managedListeners.listeners[1].tlsConfig.SessionTicketKey {
		t.Error("Expected listeners to have unique TLS session ticket keys.")
	}

	Shutdown()

	// Ensure that there are no managed listeners after shutting down.
	if len(managedListeners.listeners) != 0 {
		t.Errorf("Expected no managed listeners, received '%v'.", len(managedListeners.listeners))
	}

	// Ensure that the server is no longer accepting connections.
	for addr, serverName := range addrToServerName {
		if err := requestFailure(addr, serverName, simpleRoute); err != nil {
			t.Error(err)
		}
	}
}

func TestGracefulShutdown(t *testing.T) {
	// FIXME: I can very easily manually test this, but I can't for the life
	// of me find a way to successfully test it here.
}

func TestReuseListeners(t *testing.T) {
	if err := HTTPS(addrs, keyPairs, nil); err != nil {
		t.Fatalf("Expected no error when starting server, received '%v'.", err)
	}
	defer Shutdown()
	Serve()

	// Ensure that the server is accepting connections.
	for addr, serverName := range addrToServerName {
		if err := requestSuccess(addr, serverName, simpleRoute); err != nil {
			t.Fatal(err)
		}
	}

	// Store the current TLS session ticket keys.
	tlsSessionTicketKeys := make(map[string][32]byte)
	for _, li := range managedListeners.listeners {
		tlsSessionTicketKeys[li.Addr().String()] = li.tlsConfig.SessionTicketKey
	}

	existingListeners := Detach()

	// The server should reuse the existing listeners.
	if err := HTTPS(addrs, keyPairs, existingListeners); err != nil {
		t.Fatalf("Expected no error when restarting server, received '%v'.", err)
	}
	Serve()

	// Ensure that the server is still accepting connections.
	for addr, serverName := range addrToServerName {
		if err := requestSuccess(addr, serverName, simpleRoute); err != nil {
			t.Fatal(err)
		}
	}

	// Ensure that the TLS session ticket keys haven't changed.
	for _, li := range managedListeners.listeners {
		expectedKey, exists := tlsSessionTicketKeys[li.Addr().String()]
		if !exists {
			t.Errorf("Expected TLS session ticket key for %v to exist.", li.Addr().String())
		} else if expectedKey != li.tlsConfig.SessionTicketKey {
			t.Errorf("Expected TLS session ticket key for %v to not change.", li.Addr().String())
		}
	}
}

// request makes a request to the given server.
func request(addr, serverName, route string, expectSuccess bool) error {
	httpTransport.TLSClientConfig.ServerName = serverName
	url := "https://" + addr + route
	resp, err := httpClient.Get(url)
	if err == nil {
		resp.Body.Close()
	}

	if expectSuccess {
		if err != nil {
			return fmt.Errorf("Expected no error from %v, received '%v'.", url, err)
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("Expected status code 200 from %v, received '%v'.", url, resp.StatusCode)
		}
	} else {
		if err == nil {
			return fmt.Errorf("Expected an error from %v, received none.", url)
		}
	}

	return nil
}

// requestSuccess makes a request to the given server, and expects it to succeed.
func requestSuccess(addr, serverName, route string) error {
	return request(addr, serverName, route, true)
}

// requestFailure makes a request to the given server, and expects it to fail.
func requestFailure(addr, serverName, route string) error {
	return request(addr, serverName, route, false)
}

func simpleHandler(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintln(w, "Success")
}

func longRunningHandler(w http.ResponseWriter, req *http.Request) {
	time.Sleep(2 * time.Second)
	fmt.Fprintln(w, "Success")
}
