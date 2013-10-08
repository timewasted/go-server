go-server
=========

An easy to use HTTP/HTTPS server written in Go.  It uses the standard library, and provides some benefits over using the standard library directly:

* Can gracefully shut down active connections.
* Can detach and reattach listeners, which allows for low (zero?) downtime restarts.

Usage is simple:

```
import (
	"github.com/timewasted/go-server"
	...
)

// Create a few listeners.
httpServer := server.New()
if err := httpServer.Listen("127.0.0.1:80"); err != nil {
	log.Fatal("Listen error:", err)
}
if err := httpServer.Listen("127.0.0.1:8080"); err != nil {
	log.Fatal("Listen error:", err)
}
// Start serving connections.
httpServer.Serve()
// Shutdown the server.
httpServer.Shutdown()

// Create a few listeners.
httpsServer := server.New()
if err := httpsServer.Listen("127.0.0.1:443"); err != nil {
	log.Fatal("Listen error:", err)
}
if err := httpsServer.Listen("127.0.0.1:44380"); err != nil {
	log.Fatal("Listen error:", err)
}
// Enable TLS
if err := httpsServer.AddTLSCertificateFromFile("/path/to/server.cert", "/path/to/server.key"); err != nil {
	log.Fatal("TLS error:", err)
}
// Start serving connections.
httpsServer.Serve()
// Shutdown the server.
httpsServer.Shutdown()
```

Current limitations:
--------------------

* It is only possible to enable TLS on listeners that are detached or not currently serving connections.
* Once TLS has been enabled, it is only possible to disable it by detaching and reattaching listeners.

License:
--------
```
Copyright (c) 2013, Ryan Rogers
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met: 

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer. 
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution. 

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
