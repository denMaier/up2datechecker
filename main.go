// Up2Date shows which of your servers have pending updates, security updates or a pending
// reboot. The same binary is the dashboard (`up2date serve`) and the agent on each server
// (`up2date agent`), which reports to it from a daily timer.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// version is set at build time with -ldflags "-X main.version=…"
var version = "dev"

const usage = `usage:
  up2date serve            run the dashboard (configured by UP2DATE_* variables)
  up2date agent [flags]    report this machine's updates to the dashboard
      -dry-run             print the report instead of sending it
      -no-refresh          do not refresh the package lists first
  up2date update [flags]   install the newest release over this binary
      -same-major          stay on the current major version
  up2date version
`

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve()
	case "agent":
		err = runAgent(os.Args[2:])
	case "update":
		err = runUpdate(os.Args[2:])
	case "version", "-version", "--version":
		fmt.Println(version)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		log.SetFlags(0)
		log.Fatal(err)
	}
}

func serve() error {
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	store, err := OpenStore(filepath.Join(cfg.StateDir, "hosts.json"))
	if err != nil {
		return err
	}
	log.Printf("up2date %s listening on %s", version, cfg.Listen)
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           NewServer(cfg, store).Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	return srv.ListenAndServe()
}
