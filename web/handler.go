package web

import (
	"io/fs"
	"net/http"
	"strings"
)

// Handler mengembalikan http.Handler yang serve SPA (Single Page Application).
// File statis disajikan dari FS yang ter-embed.
// Jika file tidak ditemukan (SPA route seperti /dashboard, /nodes, dst),
// fallback ke index.html agar client-side router Framework7 yang handle.
func Handler() http.Handler {
	sub, err := fs.Sub(FS, "dist")
	if err != nil {
		panic("web: gagal sub FS: " + err.Error())
	}
	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}

		if _, err := sub.Open(p); err != nil {
			// SPA fallback: route tidak dikenal → index.html
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			fileServer.ServeHTTP(w, r2)
			return
		}

		fileServer.ServeHTTP(w, r)
	})
}
