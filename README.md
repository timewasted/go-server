go-server
=========

An easy to use HTTPS server written in Go.  It uses the standard library, and provides some benefits over using the standard library directly:

* Can gracefully shut down active connections.
* Can detach and reattach listeners, which allows for low (zero?) downtime restarts.

Usage is simple:

```
import (
	"github.com/timewasted/go-server"
	...
)

// Listen on localhost on ports 443 and 44380.
addrs := []string{
	"127.0.0.1:443",
	"127.0.0.1:44380",
}

// The above addresses are serving server1.example.com and server2.example.com.
keyPairs := map[string]string{
	"server1.example.com.crt": "server1.example.com.key",
	"server2.example.com.crt": "server2.example.com.key",
}

// Create the server.
if err := server.HTTPS(addrs, keyPairs, nil); if err != nil {
	log.Fatal("Error starting server:", err)
}

// Serve connections.
server.Serve()

// When done serving, shutdown.
server.Shutdown()
```

Current limitations:
--------------------

* Only supports HTTPS, and not plain HTTP.  I am not strictly against adding support for plain HTTP, but I generally feel that plain HTTP is not a valid option these days, so it's pretty low on my list of priorities.

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
