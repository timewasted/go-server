// Copyright 2013 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package server provides an easy to use HTTPS server.
package server

import (
	"crypto/tls"
)

// A list of the possible cipher suite ids that are not already defined
// by the crypto/tls package. Taken from
// http://www.iana.org/assignments/tls-parameters/tls-parameters.xml
// Note that the reason they are not defined by the crypto/tls package is
// because they are only usable in TLS 1.2, which is not yet supported by Go.
const (
	TLS_RSA_WITH_AES_128_GCM_SHA256       uint16 = 0x009c
	TLS_RSA_WITH_AES_256_GCM_SHA384       uint16 = 0x009d
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 uint16 = 0xc02f
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 uint16 = 0xc030
)

// ListenAndServeTLS listens on the given addresses and serves the incoming TLS
// connections.
func ListenAndServeTLS(addrs []string, serverName string, certFile string, keyFile string) error {
	tlsConfig, err := configureTLS(serverName, certFile, keyFile)
	if err != nil {
		return err
	}

	for _, addr := range addrs {
		li, err := newListener(addr, tlsConfig)
		if err != nil {
			// FIXME: We should probably continue iterating through the addresses.
			return err
		}
		go li.serve()
	}

	return err
}

// configureTLS returns a TLS configuration that will be used by listeners.
func configureTLS(serverName string, certFile string, keyFile string) (*tls.Config, error) {
	// Basic TLS configuration.
	config := &tls.Config{
		NextProtos: []string{"http/1.1"},
		ServerName: serverName,
		CipherSuites: []uint16{
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		},
		PreferServerCipherSuites: true,  // Prefer our strong ciphers
		SessionTicketsDisabled:   false, // Support session resumption
	}

	// Load the server's certificate.
	var err error
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// Shutdown gracefully closes all currently active listeners.
func Shutdown() {
	activeListeners.shutdown(true)
}

// ForceShutdown forcefully closes all currently active listeners.
func ForceShutdown() {
	activeListeners.shutdown(false)
}

/*
// Suspend prevents listeners from accepting new connections.
func Suspend() {
	// FIXME: Implement this.
}

// Resume allows listeners to continue accepting new connections.
func Resume() {
	// FIXME: Implement this.
}
*/
