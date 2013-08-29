// Copyright 2013 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package server provides an easy to use HTTPS server.
package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
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

// ListenAndServe spawns new listeners, and serves connections from those listeners.
func ListenAndServe(addrs []string, serverName string, certFile string, keyFile string) error {
	var err error

	// Do basic TLS configuration.
	tlsConfig := &tls.Config{
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
	tlsConfig.Certificates = make([]tls.Certificate, 1)
	tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	for _, addr := range addrs {
		// Listen for new connections.
		l := &listener{
			tlsConfig: tlsConfig,
			shutdown:  make(chan interface{}),
		}
		l.Listener, err = net.Listen("tcp", addr)
		if err != nil {
			// FIXME: We should probably continue iterating through the addresses.
			return err
		}
		activeListeners.watch(l)
		tlsListener := tls.NewListener(l, l.tlsConfig)

		// Serve the connections.
		go serve(l, tlsListener)

		// Since http.Serve() blocks indefinitely on Accept() with no way to
		// signal it to stop blocking, we have to resort to Dial()ing the
		// listener to force it to check to see if it should shut down.
		// FIXME: This is a hack.  There has to be a better way to do this,
		// short of reimplementing http.Serve().
		go func(l *listener) {
			<-l.shutdown
			if c, err := tls.Dial("tcp", l.Addr().String(), l.tlsConfig); err == nil {
				c.Close()
			}
		}(l)
	}

	return err
}

// serve handles serving connections, and cleaning up listeners that fail.
func serve(l *listener, tlsListener net.Listener) {
	defer activeListeners.unwatch(l)

	if err := http.Serve(tlsListener, ServeMux); err != nil {
		if _, requested := err.(*shutdownRequestedError); !requested {
			// FIXME: Implement restarting of listeners that failed.
			panic(fmt.Errorf("Failed to serve connection: %v", err))
		}
	}
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
