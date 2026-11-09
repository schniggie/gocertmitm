package webui

import (
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maxListedHosts     = 5000
	maxListedExchanges = 1000
	defaultViewBytes   = 1 << 20  // 1 MiB shown inline by default
	maxViewBytes       = 16 << 20 // hard cap for inline viewing
)

// PayloadHost summarises the captured payloads for one host directory
type PayloadHost struct {
	Name     string    `json:"name"`
	Files    int       `json:"files"`
	Bytes    int64     `json:"bytes"`
	Modified time.Time `json:"modified"`
}

// PayloadFile is one file belonging to an exchange
type PayloadFile struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// PayloadExchange groups the request/response files sharing a request ID
type PayloadExchange struct {
	ID           string       `json:"id"`
	Time         time.Time    `json:"time"`
	RequestMeta  *PayloadFile `json:"request_meta,omitempty"`
	RequestBody  *PayloadFile `json:"request_body,omitempty"`
	ResponseMeta *PayloadFile `json:"response_meta,omitempty"`
	ResponseBody *PayloadFile `json:"response_body,omitempty"`
}

// validPathComponent accepts a single, non-special directory entry name
func validPathComponent(name string) bool {
	if name == "" || name == "." || name == ".." || len(name) > 255 {
		return false
	}
	return !strings.ContainsAny(name, "/\\\x00")
}

// openPayloadRoot opens the payload directory as an os.Root, which refuses
// any path (including via symlinks) that resolves outside of it
func (s *Server) openPayloadRoot() (*os.Root, error) {
	dir := s.cfg.Backend.PayloadDir()
	if dir == "" {
		return nil, fs.ErrNotExist
	}
	return os.OpenRoot(dir)
}

func (s *Server) handlePayloadHosts(w http.ResponseWriter, r *http.Request) {
	root, err := s.openPayloadRoot()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeJSON(w, http.StatusOK, []PayloadHost{})
			return
		}
		s.cfg.Logger.Errorf("[WEBUI] Failed to open payload directory: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "cannot open payload directory")
		return
	}
	defer root.Close()

	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "cannot read payload directory")
		return
	}

	hosts := make([]PayloadHost, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		h := PayloadHost{Name: e.Name()}
		files, err := fs.ReadDir(root.FS(), e.Name())
		if err != nil {
			continue
		}
		for _, f := range files {
			info, err := f.Info()
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			h.Files++
			h.Bytes += info.Size()
			if info.ModTime().After(h.Modified) {
				h.Modified = info.ModTime()
			}
		}
		hosts = append(hosts, h)
	}

	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Modified.After(hosts[j].Modified) })
	if len(hosts) > maxListedHosts {
		hosts = hosts[:maxListedHosts]
	}
	writeJSON(w, http.StatusOK, hosts)
}

// parsePayloadName splits "req_20060102_150405.000_REQ-0001.meta" into its
// direction, timestamp, exchange ID and kind
func parsePayloadName(name string) (dir string, ts time.Time, id string, kind string, ok bool) {
	switch {
	case strings.HasPrefix(name, "req_"):
		dir, name = "req", name[len("req_"):]
	case strings.HasPrefix(name, "resp_"):
		dir, name = "resp", name[len("resp_"):]
	default:
		return "", time.Time{}, "", "", false
	}

	switch {
	case strings.HasSuffix(name, ".meta"):
		kind, name = "meta", strings.TrimSuffix(name, ".meta")
	case strings.HasSuffix(name, ".body"):
		kind, name = "body", strings.TrimSuffix(name, ".body")
	default:
		return "", time.Time{}, "", "", false
	}

	const layout = "20060102_150405.000"
	if len(name) < len(layout)+2 || name[len(layout)] != '_' {
		return "", time.Time{}, "", "", false
	}
	t, err := time.ParseInLocation(layout, name[:len(layout)], time.Local)
	if err != nil {
		return "", time.Time{}, "", "", false
	}
	return dir, t, name[len(layout)+1:], kind, true
}

func (s *Server) handlePayloadExchanges(w http.ResponseWriter, r *http.Request) {
	host := r.PathValue("host")
	if !validPathComponent(host) {
		writeJSONError(w, http.StatusBadRequest, "invalid host")
		return
	}
	filterID := r.URL.Query().Get("id")

	root, err := s.openPayloadRoot()
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "no payloads")
		return
	}
	defer root.Close()

	entries, err := fs.ReadDir(root.FS(), host)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "unknown host")
		return
	}

	byID := make(map[string]*PayloadExchange)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		dir, ts, id, kind, ok := parsePayloadName(e.Name())
		if !ok || (filterID != "" && id != filterID) {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}

		ex, exists := byID[id]
		if !exists {
			ex = &PayloadExchange{ID: id, Time: ts}
			byID[id] = ex
		}
		if ts.Before(ex.Time) {
			ex.Time = ts
		}

		f := &PayloadFile{Name: e.Name(), Size: info.Size()}
		switch dir + "/" + kind {
		case "req/meta":
			ex.RequestMeta = f
		case "req/body":
			ex.RequestBody = f
		case "resp/meta":
			ex.ResponseMeta = f
		case "resp/body":
			ex.ResponseBody = f
		}
	}

	exchanges := make([]PayloadExchange, 0, len(byID))
	for _, ex := range byID {
		exchanges = append(exchanges, *ex)
	}
	sort.Slice(exchanges, func(i, j int) bool {
		if !exchanges[i].Time.Equal(exchanges[j].Time) {
			return exchanges[i].Time.After(exchanges[j].Time)
		}
		return exchanges[i].ID > exchanges[j].ID
	})
	if len(exchanges) > maxListedExchanges {
		exchanges = exchanges[:maxListedExchanges]
	}
	writeJSON(w, http.StatusOK, exchanges)
}

// handlePayloadFile serves a captured file. Content is attacker controlled,
// so it is only ever returned as text/plain (inline view, truncated) or as an
// octet-stream attachment (download).
func (s *Server) handlePayloadFile(w http.ResponseWriter, r *http.Request) {
	host, file := r.PathValue("host"), r.PathValue("file")
	if !validPathComponent(host) || !validPathComponent(file) {
		writeJSONError(w, http.StatusBadRequest, "invalid path")
		return
	}
	if _, _, _, _, ok := parsePayloadName(file); !ok {
		writeJSONError(w, http.StatusBadRequest, "not a payload file")
		return
	}

	root, err := s.openPayloadRoot()
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "no payloads")
		return
	}
	defer root.Close()

	f, err := root.Open(host + "/" + file)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "file not found")
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		writeJSONError(w, http.StatusNotFound, "file not found")
		return
	}

	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(host, `"`, "_")+"_"+file+`"`)
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
		_, _ = io.Copy(w, f)
		return
	}

	limit := int64(defaultViewBytes)
	if v := r.URL.Query().Get("max"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			limit = min(n, maxViewBytes)
		}
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Payload-Size", strconv.FormatInt(info.Size(), 10))
	if info.Size() > limit {
		w.Header().Set("X-Payload-Truncated", "1")
	}
	_, _ = io.Copy(w, io.LimitReader(f, limit))
}
