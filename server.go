// Copyright 2013 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package server provides an easy to use HTTPS server.  It provides some
// benefits over using the standard library directly, such as the ability to
// gracefully shut down active connections, and to do low (zero?) downtime
// restarts.
package server

import (
	"crypto/tls"
	"syscall"
)

// A list of the possible cipher suite ids that are not already defined
// by the crypto/tls package. Taken from
// http://www.iana.org/assignments/tls-parameters/tls-parameters.xml
//
// Note that the reason they are not defined by the crypto/tls package is
// because they are only usable in TLS 1.2, which is not yet supported by Go.
const (
	TLS_RSA_WITH_AES_128_GCM_SHA256       uint16 = 0x009c
	TLS_RSA_WITH_AES_256_GCM_SHA384       uint16 = 0x009d
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 uint16 = 0xc02f
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 uint16 = 0xc030
)

// HTTPS creates a server that will serve HTTP requests using TLS.  If
// reuseListeners (obtained via Detach) is provided and matches an address in
// addrs, an attempt will be made to reuse the listener.  If that fails, it
// will fall back to creating a new listener.
func HTTPS(addrs []string, serverName string, certFile string, keyFile string, reuseListeners DetachedListeners) error {
	var err error

	// Load the server's certificate.
	tlsCertificates := make([]tls.Certificate, 1)
	tlsCertificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	for _, addr := range addrs {
		// Configure TLS for each individual address to avoid all addresses
		// sharing the same SessionTicketKey.
		tlsConfig := &tls.Config{
			Certificates: tlsCertificates,
			NextProtos:   []string{"http/1.1"},
			ServerName:   serverName,
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

		var li *listener
		// Attempt to reuse one of the provided listeners.
		if reuse, exists := reuseListeners[addr]; exists {
			tlsConfig.SessionTicketKey = reuse.SessionTicketKey
			li, err = newListenerFromFd(reuse.Fd, addr, tlsConfig)
			if err != nil {
				// Failed to reuse the listener, so do some cleanup.
				tlsConfig.SessionTicketKey = [32]byte{}
				syscall.Close(int(reuse.Fd))
			}
		}

		// Create a new listener if needed.
		if li == nil || err != nil {
			li, err = newListener(addr, tlsConfig)
		}

		// If we still don't have a listener, there's nothing more we can do.
		if err != nil {
			// FIXME: We should probably continue iterating through the addresses.
			return err
		}

		go li.serve()
	}

	return err
}

// Shutdown gracefully shuts down the server, allowing any currently active
// connections to finish before doing so.
func Shutdown() {
	managedListeners.shutdown(true)
}

// ForceShutdown forcefully closes all currently active connections.  Little
// care is shown in making sure things are cleaned up, so this should generally
// only be used as a last resort.
func ForceShutdown() {
	managedListeners.shutdown(false)
}

// Detach returns information about all currently active listeners.  This
// information can be passed back to HTTPS in order to recreate the listeners.
func Detach() DetachedListeners {
	return managedListeners.detach()
}
