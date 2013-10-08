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
}

func testServer() *Server {
	server := New()
	server.ServeMux.HandleFunc(simpleRoute, simpleHandler)
	server.ServeMux.HandleFunc(longRunningRoute, longRunningHandler)
	return server
}

func TestServerHTTP(t *testing.T) {
	var err error
	server := testServer()
	defer server.Shutdown()

	for _, addr := range addrs {
		if err = server.Listen(addr); err != nil {
			t.Fatalf("Expected no error when listening, received '%v'.", err)
		}
	}
	server.Serve()

	// Ensure that the server is accepting HTTP connections.
	for addr := range addrToServerName {
		if err = httpRequestSuccess(addr, simpleRoute); err != nil {
			t.Fatal(err)
		}
	}

	// Ensure that listeners can not enable TLS after serving connections.
	for certFile, keyFile := range keyPairs {
		if err = server.AddTLSCertificateFromFile(certFile, keyFile); err != nil {
			t.Fatalf("Expected no error when adding TLS certificate, received '%v'.", err)
		}
	}
	for _, listener := range server.listeners.listeners {
		if listener.tlsConfigured() {
			t.Fatal("Expected TLS to not be configured.")
		}
	}

	server.Shutdown()

	// Ensure that the server has no listeners.
	if len(server.listeners.listeners) != 0 {
		t.Errorf("Expected no managed listeners, received '%v'.", len(server.listeners.listeners))
	}

	// Ensure that the server is no longer accepting connections.
	for addr := range addrToServerName {
		if err = httpRequestFailure(addr, simpleRoute); err != nil {
			t.Error(err)
		}
	}
}

func TestServerHTTPS(t *testing.T) {
	var err error
	server := testServer()
	defer server.Shutdown()

	for _, addr := range addrs {
		if err = server.Listen(addr); err != nil {
			t.Fatalf("Expected no error when listening, received '%v'.", err)
		}
	}

	for certFile, keyFile := range keyPairs {
		if err = server.AddTLSCertificateFromFile(certFile, keyFile); err != nil {
			t.Fatalf("Expected no error when adding TLS certificate, received '%v'.", err)
		}
	}
	server.Serve()

	// Ensure that the server is accepting connections.
	for addr, serverName := range addrToServerName {
		if err = httpsRequestSuccess(addr, serverName, simpleRoute); err != nil {
			t.Fatal(err)
		}
	}

	// Ensure that SNI is working.
	if err = httpsRequestFailure(addrToServerName[addrs[0]], "invalid.example.com", simpleRoute); err != nil {
		t.Fatal(err)
	}

	// Ensure that each listener has a unique TLS session ticket key.
	if server.listeners.listeners[0].tlsConfig.SessionTicketKey ==
		server.listeners.listeners[1].tlsConfig.SessionTicketKey {
		t.Errorf("Expected listeners to have unique TLS session ticket keys.")
	}

	// Ensure that listeners can not disable TLS after serving connections.
	for _, listener := range server.listeners.listeners {
		if !listener.tlsConfigured() {
			t.Fatal("Expected TLS to be configured.")
		}
	}

	server.Shutdown()

	// Ensure that the server has no listeners.
	if len(server.listeners.listeners) != 0 {
		t.Errorf("Expected no managed listeners, received '%v'.", len(server.listeners.listeners))
	}

	// Ensure that the server is no longer accepting connections.
	for addr, serverName := range addrToServerName {
		if err = httpsRequestFailure(addr, serverName, simpleRoute); err != nil {
			t.Error(err)
		}
	}
}

func TestGracefulShutdown(t *testing.T) {
	// FIXME: I can very easily manually test this, but I can't for the life
	// of me find a way to successfully test it here.
}

func TestReuseListeners(t *testing.T) {
	var err error
	server := testServer()
	defer server.Shutdown()

	for _, addr := range addrs {
		if err = server.Listen(addr); err != nil {
			t.Fatalf("Expected no error when listening, received '%v'.", err)
		}
	}

	for certFile, keyFile := range keyPairs {
		if err = server.AddTLSCertificateFromFile(certFile, keyFile); err != nil {
			t.Fatalf("Expected no error when adding TLS certificate, received '%v'.", err)
		}
	}
	server.Serve()

	// Ensure that the server is accepting connections.
	for addr, serverName := range addrToServerName {
		if err = httpsRequestSuccess(addr, serverName, simpleRoute); err != nil {
			t.Fatal(err)
		}
	}

	// Store the current TLS session ticket keys.
	sessionTicketKeys := make(map[string][32]byte)
	for _, listener := range server.listeners.listeners {
		sessionTicketKeys[listener.Addr().String()] = listener.tlsConfig.SessionTicketKey
	}

	detachedListeners := server.Detach()

	// Ensure that the server has two listeners.
	if len(server.listeners.listeners) != 2 {
		t.Errorf("Expected two managed listeners, received '%v'.", len(server.listeners.listeners))
	}

	server.ReuseListeners(detachedListeners)
	for _, addr := range addrs {
		if err = server.Listen(addr); err != nil {
			t.Fatalf("Expected no error when listening, received '%v'.", err)
		}
	}

	for certFile, keyFile := range keyPairs {
		if err = server.AddTLSCertificateFromFile(certFile, keyFile); err != nil {
			t.Fatalf("Expected no error when adding TLS certificate, received '%v'.", err)
		}
	}
	server.Serve()

	// Ensure that the server is accepting connections.
	for addr, serverName := range addrToServerName {
		if err = httpsRequestSuccess(addr, serverName, simpleRoute); err != nil {
			t.Fatal(err)
		}
	}

	// Ensure that the TLS session ticket keys have been regenerated.
	for _, listener := range server.listeners.listeners {
		key, exists := sessionTicketKeys[listener.Addr().String()]
		if !exists {
			t.Errorf("Expected TLS session ticket key for %v to exist.", listener.Addr().String())
		} else if key == listener.tlsConfig.SessionTicketKey {
			t.Errorf("Expected TLS session ticket key for %v to be regenerated.", listener.Addr().String())
		}
	}
}

// request makes a request to the given server.
func request(tls bool, addr, serverName, route string, expectSuccess bool) error {
	var url string
	if tls {
		httpTransport.TLSClientConfig.ServerName = serverName
		url = "https://" + addr + route
	} else {
		url = "http://" + addr + route
	}
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

// httpRequestSuccess makes a plain HTTP request, which should succeed, to the
// given server.
func httpRequestSuccess(addr, route string) error {
	return request(false, addr, "", route, true)
}

// httpRequestSuccess makes a plain HTTP request, which should fail, to the
// given server.
func httpRequestFailure(addr, route string) error {
	return request(false, addr, "", route, false)
}

// httpRequestSuccess makes a HTTPS request, which should succeed, to the given
// server.
func httpsRequestSuccess(addr, serverName, route string) error {
	return request(true, addr, serverName, route, true)
}

// httpRequestSuccess makes a HTTPS request, which should fail, to the given
// server.
func httpsRequestFailure(addr, serverName, route string) error {
	return request(true, addr, serverName, route, false)
}

func simpleHandler(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintln(w, "Success")
}

func longRunningHandler(w http.ResponseWriter, req *http.Request) {
	time.Sleep(2 * time.Second)
	fmt.Fprintln(w, "Success")
}
