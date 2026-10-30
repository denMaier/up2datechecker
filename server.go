package main

import (
	"bytes"
	"cmp"
	"embed"
	"encoding/json"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

//go:embed templates static
var assets embed.FS

type Server struct {
	cfg   *Config
	auth  *Authenticator
	store *Store
	pages map[string]*template.Template
	now   func() time.Time
}

func NewServer(cfg *Config, store *Store) *Server {
	funcs := template.FuncMap{
		"ago": func(t time.Time) string {
			if t.IsZero() {
				return "never"
			}
			return humanDuration(time.Since(t)) + " ago"
		},
		"date": func(t time.Time) string { return t.Local().Format("2006-01-02 15:04") },
		"unitAction": func(host, key, action, label string) map[string]string {
			return map[string]string{"Host": host, "Key": key, "Action": action, "Label": label}
		},
	}
	pages := map[string]*template.Template{}
	for _, p := range []string{"dashboard", "host", "token", "settings"} {
		pages[p] = template.Must(template.New("layout.html").Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/"+p+".html"))
	}
	return &Server{cfg: cfg, auth: &Authenticator{cfg: cfg}, store: store, pages: pages, now: time.Now}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", s.auth.HandleLogin)
	mux.HandleFunc("GET /auth/callback", s.auth.HandleCallback)
	mux.HandleFunc("GET /auth/logout", s.auth.HandleLogout)

	// Agents authenticate with their host's bearer token, not a session
	mux.HandleFunc("POST /api/report", s.report)

	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))

	mux.Handle("GET /{$}", s.requireSession(s.dashboard))
	mux.Handle("GET /hosts/{name}", s.requireSession(s.host))
	mux.Handle("POST /hosts", s.requireSession(s.addHost))
	mux.Handle("POST /hosts/{name}/token", s.requireSession(s.rotateToken))
	mux.Handle("POST /hosts/{name}/delete", s.requireSession(s.deleteHost))
	mux.Handle("POST /hosts/{name}/units", s.requireSession(s.setUnit))
	mux.Handle("GET /settings", s.requireSession(s.settings))
	mux.Handle("POST /settings", s.requireSession(s.saveSettings))

	// Rejects cross-site form posts by their Sec-Fetch-Site or Origin header, on top of the
	// SameSite session cookie. Agents send neither header, so their reports pass.
	return securityHeaders(http.NewCrossOriginProtection().Handler(mux))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		// No scripts at all
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireSession(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.auth.Session(r); !ok {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/auth/login?next="+r.URL.EscapedPath(), http.StatusFound)
			} else {
				http.Error(w, "not signed in", http.StatusUnauthorized)
			}
			return
		}
		next(w, r)
	})
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, page string, data map[string]any) {
	sess, _ := s.auth.Session(r)
	data["User"] = sess.Name
	data["Version"] = version
	var buf bytes.Buffer
	if err := s.pages[page].Execute(&buf, data); err != nil {
		log.Printf("render %s: %v", page, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

/* Agent reports */

const maxReportBytes = 2 << 20

// POST /api/report with Authorization: Bearer <token>. The token decides which host the
// report belongs to; a host can only ever overwrite its own record.
func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	name, known := s.store.Authenticate(strings.TrimSpace(token))
	if !ok || !known {
		http.Error(w, "unknown token", http.StatusUnauthorized)
		return
	}
	var rep Report
	// Unknown fields are ignored, so a newer agent can report to an older server
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxReportBytes)).Decode(&rep); err != nil {
		http.Error(w, "invalid report: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := rep.sanitize(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.SaveReport(name, &rep, s.now()); err != nil {
		log.Printf("saving report of %s: %v", name, err)
		http.Error(w, "could not save the report", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

/* Pages */

type hostRow struct {
	Host
	Status   Status
	Reasons  []string
	Security int
	Failed   int // failed units that count
}

func (s *Server) policy() Policy {
	return Policy{StaleAge: s.cfg.StaleAge, IgnoreUnits: s.store.IgnorePatterns()}
}

func (s *Server) row(h Host, p Policy) hostRow {
	now := s.now()
	row := hostRow{Host: h, Status: h.Status(p, now), Reasons: h.Reasons(p, now), Failed: h.FailedCount(p)}
	if h.Report != nil {
		row.Security = h.Report.SecurityCount()
	}
	return row
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	s.renderDashboard(w, r, http.StatusOK, "")
}

func (s *Server) renderDashboard(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	hosts := s.store.List()
	rows := make([]hostRow, 0, len(hosts))
	counts := map[string]int{}
	p := s.policy()
	for _, h := range hosts {
		row := s.row(h, p)
		counts[row.Status.String()]++
		rows = append(rows, row)
	}
	// Most urgent first, then by name
	slices.SortFunc(rows, func(a, b hostRow) int {
		return cmp.Or(cmp.Compare(a.Status, b.Status), cmp.Compare(a.Name, b.Name))
	})
	s.render(w, r, status, "dashboard", map[string]any{"Hosts": rows, "Counts": counts, "Error": errMsg})
}

func (s *Server) host(w http.ResponseWriter, r *http.Request) {
	h, ok := s.store.Get(r.PathValue("name"))
	if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	var updates []Update
	if h.Report != nil {
		updates = slices.Clone(h.Report.Updates)
		slices.SortStableFunc(updates, func(a, b Update) int {
			if a.Security != b.Security {
				if a.Security {
					return -1
				}
				return 1
			}
			return cmp.Compare(a.Name, b.Name)
		})
	}
	p := s.policy()
	var units []unitRow
	if h.Report != nil {
		for _, u := range h.Report.FailedUnits {
			q, pat := h.Quiet(u, p)
			units = append(units, unitRow{FailedUnit: u, Key: unitKey(u), Quiet: q, Pattern: pat})
		}
		// The ones that count (no Quiet reason) first
		slices.SortStableFunc(units, func(a, b unitRow) int { return cmp.Compare(len(a.Quiet), len(b.Quiet)) })
	}
	s.render(w, r, http.StatusOK, "host", map[string]any{"H": s.row(h, p), "Updates": updates, "Units": units})
}

type unitRow struct {
	FailedUnit
	Key     string
	Quiet   string // why it does not count, see Host.Quiet
	Pattern string
}

// POST /hosts/{name}/units: unit=<unitKey>, action=ignore|unignore|ack|unack
func (s *Server) setUnit(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.store.SetUnit(name, r.PostFormValue("unit"), r.PostFormValue("action")); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/hosts/"+url.PathEscape(name)+"#services", http.StatusSeeOther)
}

func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	s.renderSettings(w, r, http.StatusOK, strings.Join(s.store.IgnorePatterns(), "\n"), "")
}

func (s *Server) renderSettings(w http.ResponseWriter, r *http.Request, status int, patterns, errMsg string) {
	// Which failed units each pattern silences right now, as a check of what it does
	matches := map[string][]string{}
	p := s.policy()
	for _, h := range s.store.List() {
		if h.Report == nil {
			continue
		}
		for _, u := range h.Report.FailedUnits {
			if q, pat := h.Quiet(u, p); q == "pattern" {
				matches[pat] = append(matches[pat], h.Name+": "+u.Unit)
			}
		}
	}
	s.render(w, r, status, "settings", map[string]any{"Patterns": patterns, "Matches": matches, "Error": errMsg})
}

func (s *Server) saveSettings(w http.ResponseWriter, r *http.Request) {
	text := r.PostFormValue("ignoreUnits")
	if err := s.store.SetIgnorePatterns(strings.Split(text, "\n")); err != nil {
		s.renderSettings(w, r, http.StatusBadRequest, text, err.Error())
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) addHost(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	token, err := s.store.Add(name)
	if err != nil {
		s.renderDashboard(w, r, http.StatusBadRequest, err.Error())
		return
	}
	s.showToken(w, r, name, token, true)
}

func (s *Server) rotateToken(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	token, err := s.store.Rotate(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	s.showToken(w, r, name, token, false)
}

func (s *Server) showToken(w http.ResponseWriter, r *http.Request, name, token string, isNew bool) {
	s.render(w, r, http.StatusOK, "token", map[string]any{"Name": name, "Token": token, "New": isNew, "URL": s.cfg.PublicURL})
}

func (s *Server) deleteHost(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if r.PostFormValue("confirm") != name {
		http.Redirect(w, r, "/hosts/"+url.PathEscape(name), http.StatusSeeOther)
		return
	}
	if err := s.store.Delete(name); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
