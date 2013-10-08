// Copyright 2013 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package server provides an easy to use HTTP/HTTPS server.  It provides some
// benefits over using the standard library directly, such as the ability to
// gracefully shut down active connections, and to do low (zero?) downtime
// restarts.
package server

import (
	"crypto/tls"
	"net/http"
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

// Server is a simple HTTP/HTTPS server.
type Server struct {
	*http.ServeMux
	TLS            *tls.Config
	listeners      *listeners
	reuseListeners DetachedListeners
}

// New creates a new Server.
func New() *Server {
	return &Server{
		ServeMux:       http.NewServeMux(),
		TLS:            nil,
		listeners:      &listeners{},
		reuseListeners: DetachedListeners{},
	}
}

// ReuseListeners provides an address to file descriptor mapping of listeners
// that the server can reuse instead of creating a new listener.
func (s *Server) ReuseListeners(listeners DetachedListeners) {
	if listeners != nil {
		s.reuseListeners = listeners
	}
}

// Listen will begin listening on the given address, either by reusing an
// existing listener, or by creating a new one.
func (s *Server) Listen(addr string) error {
	if fd, exists := s.reuseListeners[addr]; exists {
		if err := s.listeners.reuse(fd, addr); err == nil {
			return nil
		}
		syscall.Close(int(fd))
	}
	return s.listeners.new(addr)
}

// AddTLSCertificate reads the certificate and private key from the provided
// PEM blocks, and adds the certificate to the list of certificates that the
// server can use.
func (s *Server) AddTLSCertificate(certPEMBlock, keyPEMBlock []byte) error {
	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return err
	}

	s.addTLSCert(cert)
	return nil
}

// AddTLSCertificateFromFile reads the certificate and private key from the
// provided file paths, and adds the certificate to the list of certificates
// that the server can use.
func (s *Server) AddTLSCertificateFromFile(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	s.addTLSCert(cert)
	return nil
}

// addTLSCert adds the provided certificate to the list of certificates that
// the server can use.
func (s *Server) addTLSCert(cert tls.Certificate) {
	if s.TLS == nil {
		s.TLS = s.initialTLSConfiguration()
	}
	s.TLS.Certificates = append(s.TLS.Certificates, cert)
	s.TLS.BuildNameToCertificate()
	s.listeners.configureTLS(s.TLS)
}

// initialTLSConfiguration returns a base TLS configuration that can then be
// customized to fit the needs of the individual server.
func (s *Server) initialTLSConfiguration() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{},
		NextProtos:   []string{"http/1.1"},
		// Reasoning behind the cipher suite ordering:
		//
		// - We want forward secrecy, so ECDHE/DHE come first. ECDHE comes
		//   before DHE since it's both stronger and faster.
		// - We prefer ECDSA over RSA since it's both stronger and faster.
		// - AES-GCM is currently our best choice of ciphers, since it is not
		//   vulnerable to any known attacks.
		// - Between CBC-mode ciphers and RC4, I'm not sure which is the lesser
		//   evil. CBC is vulnerable to BEAST (which is mostly mitigated by
		//   modern clients: https://community.qualys.com/blogs/securitylabs/2013/09/10/is-beast-still-a-threat)
		//   and Lucky13 (which is unlikely to be mitigated in Go: https://groups.google.com/d/msg/golang-nuts/HF5O5vAKRcQ/3cYWryRyZboJ),
		//   while RC4 has its own set of issues which lead to questionable
		//   security. For now, I'm opting to prefer RC4 just because that
		//   seems to be the consensus among the internet giants that employ
		//   people who are undoubtedly much smarter than me about this sort
		//   of thing.
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
		SessionTicketsDisabled:   false, // Support session tickets
	}
}

// Serve begins serving connections.
func (s *Server) Serve() {
	s.listeners.serve(s)
}

// Shutdown gracefully shuts down the server, allowing any currently active
// connections to finish before doing so.
func (s *Server) Shutdown() {
	s.listeners.shutdown(true)
}

// ForceShutdown forcefully closes all currently active connections.  Little
// care is shown in making sure things are cleaned up, so this should generally
// only be used as a last resort.
func (s *Server) ForceShutdown() {
	s.listeners.shutdown(false)
}

// Detach returns an address to file descriptor mapping for all listeners.
func (s *Server) Detach() DetachedListeners {
	return s.listeners.detach()
}

// ServeHTTP implements the ServeHTTP() method of the http.Handler interface.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.listeners.Add(1)
	defer s.listeners.Done()

	s.ServeMux.ServeHTTP(w, r)
}
