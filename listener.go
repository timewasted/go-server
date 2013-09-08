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
	stateActive   uint16 = iota
	stateServing  uint16 = 1 << iota
	stateClosing  uint16 = 1 << iota
	stateDetached uint16 = 1 << iota
)

// listener is an implementation of the net.Listener interface.
type listener struct {
	net.Listener
	tlsConfig *tls.Config
	state     uint16
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
		state:     stateActive,
	}
	managedListeners.manage(l)

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
		state:     stateActive,
	}
	managedListeners.manage(l)

	return l, nil
}

// Accept implements the Accept() method of the net.Listener interface.
func (l *listener) Accept() (c net.Conn, err error) {
	c, err = l.Listener.Accept()
	if err != nil {
		// FIXME: I'm not sure this is safe to check concurrently.
		if l.state&stateClosing != 0 {
			err = errShutdownRequested
		}
		return
	}
	c = tls.Server(c, l.tlsConfig)
	return
}

// Close implements the Close() method of the net.Listener interface.
func (l *listener) Close() error {
	err := l.Listener.Close()
	// FIXME: I'm not fond of having to do this in a goroutine, but it's the
	// least terrible option available.
	go managedListeners.unmanage(l)
	return err
}

// serve handles serving connections, and cleaning up listeners that fail.
func (l *listener) serve() {
	if err := http.Serve(l, ServeMux); err != nil {
		if _, requested := err.(*shutdownRequestedError); !requested {
			// FIXME: Do something useful here.  Just panicing isn't even
			// remotely useful.
			panic(fmt.Errorf("Failed to serve connection: %v", err))
		}
	}
}

// listeners is the container used by managedListeners.
type listeners struct {
	listeners []*listener
	sync.RWMutex
	sync.WaitGroup
}

// manage starts managing the provided listener.
func (l *listeners) manage(li *listener) {
	l.Lock()
	l.listeners = append(l.listeners, li)
	l.Add(1)
	l.Unlock()
}

// unmanage stops managing the provided listener.
func (l *listeners) unmanage(li *listener) {
	l.Lock()
	for i, ml := range l.listeners {
		if ml == li {
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

// serve begins serving connections.
func (l *listeners) serve() {
	l.RLock()
	for _, li := range l.listeners {
		// Ignore listeners that are closing or already serving.
		if li.state&stateClosing != 0 || li.state&stateServing != 0 {
			continue
		}

		li.state |= stateServing
		go li.serve()
	}
	l.RUnlock()
}

// shutdown starts the shutdown process for all managed listeners.
func (l *listeners) shutdown(graceful bool) {
	l.RLock()
	for _, li := range l.listeners {
		// Ignore listeners that are closing.
		if li.state&stateClosing != 0 {
			continue
		}

		li.state |= stateClosing
		li.Close()
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

// detach returns information about listeners which can be used to recreate the
// listener.
func (l *listeners) detach() DetachedListeners {
	l.RLock()
	detachedListeners := make(DetachedListeners)
	for _, li := range l.listeners {
		// Ignore listeners that are closing.
		if li.state&stateClosing != 0 {
			continue
		}

		netFd := reflect.ValueOf(li.Listener).Elem().FieldByName("fd").Elem()
		detachedListeners[li.Addr().String()] = &detachedListener{
			Fd:               uintptr(netFd.FieldByName("sysfd").Int()),
			SessionTicketKey: li.tlsConfig.SessionTicketKey,
		}
		li.state |= stateDetached
	}
	l.RUnlock()

	return detachedListeners
}

// managedListeners is used to manage the active listeners.
var managedListeners = &listeners{}

// detachedListener contains the information needed to recreate a listener.
type detachedListener struct {
	Fd               uintptr
	SessionTicketKey [32]byte
}

// DetachedListeners is an address => detachedListener mapping.
type DetachedListeners map[string]*detachedListener

// shutdownRequestedError is an implementation of the error interface.  It is
// used to indicate that the shutdown of a listener was requested.
type shutdownRequestedError struct{}

// Error implements the Error() method of the error interface.
func (e *shutdownRequestedError) Error() string { return "shutdown requested" }

// errShutdownRequested is the error returned by Accept when it is responding
// to a requested shutdown.
var errShutdownRequested = &shutdownRequestedError{}
