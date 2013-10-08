// Copyright 2013 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"reflect"
	"sync"
	"time"
)

// States that a listener can be in.
const (
	stateListening uint16 = iota
	stateServing   uint16 = 1 << iota
	stateClosing   uint16 = 1 << iota
	stateDetached  uint16 = 1 << iota
)

// listener is an implementation of the net.Listener interface.
type listener struct {
	net.Listener
	manager              *listeners
	stateMutex, tlsMutex sync.RWMutex
	state                uint16
	tlsConfig            *tls.Config
}

// hasState returns true if the listener has any of the states provided.  This
// is an OR check, not an AND check.
func (l *listener) hasState(states ...uint16) bool {
	l.stateMutex.RLock()
	defer l.stateMutex.RUnlock()

	for _, state := range states {
		if state == stateListening || l.state&state != 0 {
			return true
		}
	}
	return false
}

// configureTLS sets the TLS configuration for the listener.
func (l *listener) configureTLS(config *tls.Config) {
	l.tlsMutex.Lock()
	if config == nil {
		config = &tls.Config{}
	} else {
		*l.tlsConfig = *config
	}
	l.tlsMutex.Unlock()
}

// tlsConfigured returns true if TLS has been configured for the listener.
func (l *listener) tlsConfigured() bool {
	l.tlsMutex.RLock()
	defer l.tlsMutex.RUnlock()
	return len(l.tlsConfig.Certificates) > 0
}

// Accept implements the Accept() method of the net.Listener interface.
func (l *listener) Accept() (c net.Conn, err error) {
	c, err = l.Listener.Accept()
	if err != nil {
		if l.hasState(stateClosing) {
			err = errShutdownRequested
		}
		return
	}
	if l.tlsConfigured() {
		c = tls.Server(c, l.tlsConfig)
	}
	return
}

// Close implements the Close() method of the net.Listener interface.
func (l *listener) Close() error {
	err := l.Listener.Close()
	go l.manager.unmanage(l)
	return err
}

// serve begins serving connections.
func (l *listener) serve(server *Server) {
	if err := http.Serve(l, server); err != nil {
		if _, requested := err.(*shutdownRequestedError); !requested {
			// FIXME: Do something useful here.  Just panicing isn't even
			// remotely useful.
			panic(fmt.Errorf("Failed to serve connection: %v", err))
		}
	}
}

// listeners is a collection of managed listeners.
type listeners struct {
	sync.RWMutex
	sync.WaitGroup
	listeners []*listener
}

// new creates a new listener.
func (l *listeners) new(addr string) error {
	newListener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	l.manage(newListener)
	return nil
}

// reuse creates a new listener using the provided file descriptor.
func (l *listeners) reuse(fd uintptr, addr string) error {
	newListener, err := net.FileListener(os.NewFile(fd, "tcp:"+addr+"->"))
	if err != nil {
		return err
	}

	var reused bool
	l.Lock()
	for i, li := range l.listeners {
		if li.Addr().String() == addr {
			l.listeners[i] = &listener{
				Listener:  newListener,
				manager:   l,
				state:     stateListening,
				tlsConfig: &tls.Config{},
			}
			reused = true
		}
	}
	l.Unlock()

	if !reused {
		l.manage(newListener.(*net.TCPListener))
	}
	return nil
}

// manage keeps track of the provided listener.
func (l *listeners) manage(li net.Listener) {
	l.Lock()
	l.listeners = append(l.listeners, &listener{
		Listener:  li,
		manager:   l,
		state:     stateListening,
		tlsConfig: &tls.Config{},
	})
	l.Add(1)
	l.Unlock()
}

// unmanage stops keeping track of the provided listener.
func (l *listeners) unmanage(listener *listener) {
	l.Lock()
	for i, li := range l.listeners {
		if li == listener {
			l.listeners[len(l.listeners)-1], l.listeners[i], l.listeners =
				nil, l.listeners[len(l.listeners)-1], l.listeners[:len(l.listeners)-1]
			l.Done()
			break
		}
	}
	if len(l.listeners) == 0 {
		l.listeners = nil
	}
	l.Unlock()
}

// configureTLS sets the TLS configuration for each listener that is not
// serving connections or closing.
func (l *listeners) configureTLS(config *tls.Config) {
	l.RLock()
	for _, listener := range l.listeners {
		// Ignore listeners that are serving or closing.
		listener.stateMutex.RLock()
		if listener.state&(stateServing|stateClosing) == 0 {
			listener.configureTLS(config)
		}
		listener.stateMutex.RUnlock()
	}
	l.RUnlock()
}

// serve begins serving connections for each listener that is not already
// serving connections or closing.
func (l *listeners) serve(server *Server) {
	l.RLock()
	for _, listener := range l.listeners {
		// Ignore listeners that are serving or closing.
		listener.stateMutex.Lock()
		if listener.state&(stateServing|stateClosing) == 0 {
			listener.state |= stateServing
			go listener.serve(server)
		}
		listener.stateMutex.Unlock()
	}
	l.RUnlock()
}

// shutdown requests that each listener that is not already closing be shut
// down.  Is graceful is true, this function blocks until all listeners have
// been shut down.
func (l *listeners) shutdown(graceful bool) {
	l.RLock()
	for _, listener := range l.listeners {
		// Ignore listeners that are closing.
		listener.stateMutex.Lock()
		if listener.state&stateClosing == 0 {
			listener.state |= stateClosing
			listener.Close()
		}
		listener.stateMutex.Unlock()
	}
	l.RUnlock()
	if graceful {
		l.Wait()
	}

	// FIXME: Somewhat rarely, connections aren't gracefully shut down.  In
	// curl, this manifests as error 52 ("Empty reply from server").  One way
	// to work around this is to add a minor delay here.  A proper fix should
	// be investigated and implemented instead.
	time.Sleep(100 * time.Millisecond)
}

// detach returns an address to underlying file descriptor mapping for all
// listeners that are not closing.
func (l *listeners) detach() DetachedListeners {
	l.RLock()
	listeners := make(DetachedListeners)
	for _, listener := range l.listeners {
		// Ignore listeners that are closing.
		listener.stateMutex.Lock()
		if listener.state&stateClosing == 0 {
			fd := reflect.ValueOf(listener.Listener).Elem().FieldByName("fd").Elem()
			listeners[listener.Addr().String()] = uintptr(fd.FieldByName("sysfd").Int())
			listener.state |= stateDetached
		}
		listener.stateMutex.Unlock()
	}
	l.RUnlock()

	return listeners
}

// DetachedListeners is an address to file descriptor mapping of listeners that
// have been detached.
type DetachedListeners map[string]uintptr

// shutdownRequestedError is an implementation of the error interface.  It is
// used to indicate that the shutdown of a listener was requested.
type shutdownRequestedError struct{}

// Error implements the Error() method of the error interface.
func (e *shutdownRequestedError) Error() string { return "shutdown requested" }

// errShutdownRequested is the error returned by Accept when it is responding
// to a requested shutdown.
var errShutdownRequested = &shutdownRequestedError{}
