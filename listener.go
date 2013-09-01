// Copyright 2013 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"syscall"
)

// Signals that can be sent to listeners.
const (
	signalShutdown = iota
)

// listener is an implementation of the net.Listener interface that supports
// gracefully closing the listener.
type listener struct {
	net.Listener
	tlsConfig       *tls.Config
	unblock, signal chan int
}

// newListener creates a new listener.
func newListener(addr string, tlsConfig *tls.Config) (*listener, error) {
	li, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	l := &listener{
		Listener:  li,
		tlsConfig: tlsConfig,
		unblock:   make(chan int),
		signal:    make(chan int, 1),
	}
	activeListeners.watch(l)

	return l, nil
}

// newListenerFromFd creates a new listener using the provided file descriptor.
func newListenerFromFd(fd uintptr, addr string, tlsConfig *tls.Config) (*listener, error) {
	li, err := net.FileListener(os.NewFile(fd, "tcp:"+addr+"->"))
	if err != nil {
		return nil, err
	}
	l := &listener{
		Listener:  li.(*net.TCPListener),
		tlsConfig: tlsConfig,
		unblock:   make(chan int),
		signal:    make(chan int, 1),
	}
	activeListeners.watch(l)

	return l, nil
}

// Accept implements the Accept() method of the net.Listener interface.
func (l *listener) Accept() (c net.Conn, err error) {
	// Check for signals.
	select {
	case sig := <-l.signal:
		switch sig {
		case signalShutdown:
			l.close()
			return nil, errShutdownRequested
		}
	default:
	}

	c, err = l.Listener.Accept()
	return
}

// close closes the listener.
func (l *listener) close() {
	l.Close()
	activeListeners.unwatch(l)
}

// serve handles serving connections, and cleaning up listeners that fail.
func (l *listener) serve() {
	defer l.close()

	go l.unblockAccept()
	tlsListener := tls.NewListener(l, l.tlsConfig)
	if err := http.Serve(tlsListener, ServeMux); err != nil {
		if _, requested := err.(*shutdownRequestedError); !requested {
			// FIXME: Implement restarting of listeners that failed.
			panic(fmt.Errorf("Failed to serve connection: %v", err))
		}
	}
}

// unblockAccept will, upon receiving a signal, connect to the listener then
// immediately disconnect from it, in order to unblock Accept().
// FIXME: This is a hack.  It works, but there has to be a better way.
func (l *listener) unblockAccept() {
	for {
		sig := <-l.unblock
		if c, err := tls.Dial("tcp", l.Addr().String(), l.tlsConfig); err == nil {
			c.Close()
		}
		if sig == signalShutdown {
			return
		}
	}
}

// listeners is a container that keeps track of listener.
type listeners struct {
	listeners []*listener
	sync.RWMutex
	sync.WaitGroup
}

// watch keeps track of the provided listener.
func (l *listeners) watch(w *listener) {
	l.Lock()
	l.listeners = append(l.listeners, w)
	l.Add(1)
	l.Unlock()
}

// unwatch stops keeping track of the provided listener.
func (l *listeners) unwatch(w *listener) {
	l.Lock()
	for i, li := range l.listeners {
		if li == w {
			l.listeners[len(l.listeners)-1], l.listeners[i], l.listeners = nil, l.listeners[len(l.listeners)-1], l.listeners[:len(l.listeners)-1]
			l.Done()
			break
		}
	}
	if len(l.listeners) == 0 {
		l.listeners = nil
	}
	l.Unlock()
}

// shutdown closes the watched listeners.  If graceful is true, active
// connections are allowed to finish.  Otherwise, listeners are closed without
// regard to any active connections.
func (l *listeners) shutdown(graceful bool) {
	l.Lock()
	for i, li := range l.listeners {
		li.signal <- signalShutdown
		li.unblock <- signalShutdown
		if !graceful {
			li.Close()
			l.listeners[i] = nil
			l.Done()
		}
	}
	if !graceful {
		l.listeners = nil
	}
	l.Unlock()
	if graceful {
		l.Wait()
	}
}

// detach closes all active listeners, while keeping the underlying file
// descriptor open so that the listener can be recreated later.
// FIXME: This needs much better error handling.
func (l *listeners) detach() (DetachedListeners, error) {
	var err error
	var file *os.File
	var fd int

	l.RLock()
	detachedListeners := make(DetachedListeners)
	for _, li := range l.listeners {
		// Get the listener's underlying file.
		file, err = li.Listener.(*net.TCPListener).File()
		if err != nil {
			break
		}

		// Get the file descriptor of the file.
		fd, err = syscall.Dup(int(file.Fd()))
		if err != nil {
			break
		}

		detachedListeners[li.Addr().String()] = detachedListener{
			Fd:               uintptr(fd),
			sessionTicketKey: li.tlsConfig.SessionTicketKey,
		}
		li.signal <- signalShutdown
		li.unblock <- signalShutdown
	}
	l.RUnlock()
	if err != nil {
		return nil, err
	}

	l.Wait()
	return detachedListeners, nil
}

// activeListeners is a collection of the currently active listeners.
var activeListeners = &listeners{}

// detachedListener holds the information needed to detach and then recreate
// a listener.
type detachedListener struct {
	Fd               uintptr
	sessionTicketKey [32]byte
}

// DetachedListeners is an address to detachedListener mapping.
type DetachedListeners map[string]detachedListener

// shutdownRequested is an error type used to indicate that the shutdown of a
// listener was requested.
type shutdownRequestedError struct {
	error
}

// errShutdownRequested is an instance of shutdownRequestedError.
var errShutdownRequested = &shutdownRequestedError{errors.New("shutdown requested")}
