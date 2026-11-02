package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"strconv"
)

// runHTTP serves GET /down?bytes=N (N zero bytes) and POST /up (body
// discarded): the target of a tunnel benchmark, so it needs no internet.
func runHTTP(args []string) error {
	fs := flag.NewFlagSet("http", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8088", "address to listen on")
	_ = fs.Parse(args)
	mux := http.NewServeMux()
	mux.HandleFunc("/down", func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(r.URL.Query().Get("bytes"))
		if err != nil || n < 0 {
			n = 1 << 20
		}
		w.Header().Set("Content-Length", strconv.Itoa(n))
		buf := make([]byte, 32*1024)
		for n > 0 {
			chunk := min(n, len(buf))
			if _, err := w.Write(buf[:chunk]); err != nil {
				return
			}
			n -= chunk
		}
	})
	mux.HandleFunc("/up", func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(strconv.FormatInt(n, 10)))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	log.Printf("http target on %s", *listen)
	return http.ListenAndServe(*listen, mux)
}
