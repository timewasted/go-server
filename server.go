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

// A list of strong cipher suite IDs that are not defined by the crypto/tls
// package in the current stable version of Go. Values taken from
// http://www.iana.org/assignments/tls-parameters/tls-parameters.xml
//
// Note that the reason they are not defined by the crypto/tls package is
// because they are not (yet?) supported by Go. Defining them here allows us
// to immediately start using them, should Go support them in the future.
const (
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA        uint16 = 0x0033
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA        uint16 = 0x0039
	TLS_RSA_WITH_AES_128_GCM_SHA256         uint16 = 0x009c
	TLS_RSA_WITH_AES_256_GCM_SHA384         uint16 = 0x009d
	TLS_DHE_RSA_WITH_AES_128_GCM_SHA256     uint16 = 0x009e
	TLS_DHE_RSA_WITH_AES_256_GCM_SHA384     uint16 = 0x009f
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA    uint16 = 0xc009
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA    uint16 = 0xc00a
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 uint16 = 0xc02b
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 uint16 = 0xc02c
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   uint16 = 0xc02f
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   uint16 = 0xc030
)

// HTTPS creates a server that will serve HTTP requests using TLS.  If
// reuseListeners (obtained via Detach) is provided and matches an address in
// addrs, an attempt will be made to reuse the listener.  If that fails, it
// will fall back to creating a new listener.
func HTTPS(addrs []string, keyPairs map[string]string, reuseListeners DetachedListeners) error {
	// Load the server's certificates.
	tlsCertificates := make([]tls.Certificate, 0, len(keyPairs))
	for certFile, keyFile := range keyPairs {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return err
		}
		tlsCertificates = append(tlsCertificates, cert)
	}

	var err error
	for _, addr := range addrs {
		// Configure TLS for each individual address to avoid all addresses
		// sharing the same SessionTicketKey.
		tlsConfig := &tls.Config{
			Certificates: tlsCertificates,
			NextProtos:   []string{"http/1.1"},
			// Reasoning behind the cipher suite ordering:
			//
			// - We want forward secrecy, so ECDHE/DHE come first. ECDHE comes
			//   before DHE since it's both stronger and faster.
			// - We prefer ECDSA over RSA since it's both stronger and faster.
			// - AES-GCM is currently our best choice of ciphers, since it is
			//   not vulnerable to any known attacks.
			// - Between CBC-mode ciphers and RC4, I'm not sure which is the
			//   lesser evil. CBC is vulnerable to BEAST (which is mostly
			//   mitigated by modern clients: https://community.qualys.com/blogs/securitylabs/2013/09/10/is-beast-still-a-threat)
			//   and Lucky13 (which is unlikely to be mitigated in Go: https://groups.google.com/d/msg/golang-nuts/HF5O5vAKRcQ/3cYWryRyZboJ),
			//   while RC4 has its own set of issues which lead to questionable
			//   security. For now, I'm opting to prefer RC4 just because that
			//   seems to be the consensus among the internet giants that
			//   employ people who are undoubtedly much smarter than me about
			//   this sort of thing.
			CipherSuites: []uint16{
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,

				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,

				TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_DHE_RSA_WITH_AES_128_CBC_SHA,

				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_RC4_128_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			},
			PreferServerCipherSuites: true,  // Prefer our strong ciphers
			SessionTicketsDisabled:   false, // Support session resumption
		}
		tlsConfig.BuildNameToCertificate()

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
	}

	return err
}

// Serve begins serving connections.
func Serve() {
	managedListeners.serve()
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
