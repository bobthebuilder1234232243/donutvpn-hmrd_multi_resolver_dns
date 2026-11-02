// Command hmrdbench measures how much DNS traffic the pool gets through
// rate-limited, lossy or dead resolvers, and provides the pieces an
// end-to-end DNS tunnel benchmark needs.
//
//	hmrdbench bench      library benchmark: the relay against a plain
//	                     multi-resolver and a single resolver (no tunnel needed)
//	hmrdbench resolver   a rate-limited DNS resolver for tests: answers locally
//	                     or forwards to a tunnel server, refuses or drops what
//	                     exceeds its rate
//	hmrdbench http       an HTTP target for tunnel tests: GET /down?bytes=N,
//	                     POST /up
//	hmrdbench pool       the relay on a fixed local address, in front of the
//	                     given resolvers, for tunnel clients outside Go
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "bench":
		err = runBench(os.Args[2:])
	case "resolver":
		err = runResolver(os.Args[2:])
	case "http":
		err = runHTTP(os.Args[2:])
	case "pool":
		err = runPool(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "hmrdbench:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: hmrdbench bench|resolver|http|pool [flags]
  bench     library benchmark of the relay (run with -h for flags)
  resolver  rate-limited test resolver
  http      HTTP download/upload target
  pool      the relay on a fixed local address, in front of resolvers`)
	os.Exit(2)
}
