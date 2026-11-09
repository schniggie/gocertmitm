package webui

import (
	"encoding/csv"
	"net/http"
	"strings"
	"time"

	"github.com/gocertmitm/internal/proxy"
)

func exportFilename(ext string) string {
	return "certmitm-results-" + time.Now().UTC().Format("20060102T150405Z") + "." + ext
}

func (s *Server) handleExportJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Disposition", `attachment; filename="`+exportFilename("json")+`"`)
	writeJSON(w, http.StatusOK, struct {
		GeneratedAt time.Time          `json:"generated_at"`
		Info        proxy.Info         `json:"info"`
		Domains     []proxy.DomainView `json:"domains"`
	}{time.Now().UTC(), s.cfg.Backend.Info(), s.cfg.Backend.Domains()})
}

// csvSafe neutralises spreadsheet formula injection. Domain names come from
// client-supplied SNI / Host headers and must be treated as hostile.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

func (s *Server) handleExportCSV(w http.ResponseWriter, r *http.Request) {
	info := s.cfg.Backend.Info()
	domains := s.cfg.Backend.Domains()

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+exportFilename("csv")+`"`)

	cw := csv.NewWriter(w)
	header := []string{"key", "domain", "ips", "verdict", "accepted_test", "last_tested"}
	for _, t := range info.Tester.TestOrder {
		header = append(header, t.Key)
	}
	_ = cw.Write(header)

	for _, d := range domains {
		ips := d.IPs
		if len(ips) == 0 && d.IP != "" {
			ips = []string{d.IP}
		}
		row := []string{
			csvSafe(d.Key),
			csvSafe(d.Domain),
			csvSafe(strings.Join(ips, " ")),
			d.Verdict,
			d.AcceptedTest,
			d.LastTested.UTC().Format(time.RFC3339),
		}
		states := make(map[string]string, len(d.Tests))
		for _, t := range d.Tests {
			states[t.Key] = t.State
		}
		for _, t := range info.Tester.TestOrder {
			row = append(row, states[t.Key])
		}
		_ = cw.Write(row)
	}
	cw.Flush()
}
