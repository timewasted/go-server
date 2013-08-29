// Copyright 2013 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"crypto/tls"
	"errors"
	"net"
	"sync"
)

// listener is an implementation of the net.Listener interface that supports
// gracefully closing the listener.
type listener struct {
	net.Listener
	tlsConfig *tls.Config
	shutdown  chan interface{}
}

// listeners is a container that keeps track of listener.
type listeners struct {
	listeners []*listener
	sync.Mutex
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
	for _, li := range l.listeners {
		if graceful {
			close(li.shutdown)
		} else {
			li.Close()
		}
	}
	l.Unlock()
	if graceful {
		l.Wait()
	}
}

// activeListeners is a collection of the currently active listeners.
var activeListeners = &listeners{}

// shutdownRequested is an error type used to indicate that the shutdown of a
// listener was requested.
type shutdownRequestedError struct {
	error
}

// errShutdownRequested is an instance of shutdownRequestedError.
var errShutdownRequested = &shutdownRequestedError{errors.New("shutdown requested")}

// Accept implements the Accept() method of the net.Listener interface.
func (l *listener) Accept() (c net.Conn, err error) {
	// Check to see if we should shut down.
	select {
	case <-l.shutdown:
		// l.Close() isn't really needed here, since http.Serve() closes the
		// listener on return.
		l.Close()
		return nil, errShutdownRequested
	default:
	}

	c, err = l.Listener.Accept()
	return
}
