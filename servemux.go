// Copyright 2013 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"net/http"
)

// serveMux is an implementation of the http.ServeMux interface.
type serveMux struct {
	*http.ServeMux
}

// ServeMux is the muxer to be used by http.Serve().
var ServeMux = &serveMux{http.NewServeMux()}

// ServeHTTP implements the ServeHTTP() method of the http.ServeMux interface.
func (mux *serveMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	managedListeners.Add(1)
	defer managedListeners.Done()

	mux.ServeMux.ServeHTTP(w, r)
}
