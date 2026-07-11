package core

import (
	"log"
	"net/http"
	"strings"
)

// HandlerFunc adalah tipe standar untuk semua HTTP handler di HAPM.
// Mengikuti pola dari referensi apigo: func(w, r, params)
type HandlerFunc func(http.ResponseWriter, *http.Request, []string)

// Route mendefinisikan satu entri route
type Route struct {
	Method  string
	Pattern string
	Handler HandlerFunc
}

// Router adalah HTTP router HAPM berbasis net/http.ServeMux.
// Mendukung prefix /api/v1 dan path parameter extraction.
type Router struct {
	mux    *http.ServeMux
	routes []Route
}

// NewRouter membuat instance Router baru
func NewRouter() *Router {
	return &Router{
		mux:    http.NewServeMux(),
		routes: make([]Route, 0),
	}
}

// Handle mendaftarkan handler untuk method dan pattern tertentu.
// Pattern: /api/v1/nodes/{id} → params[0] = id value
func (rt *Router) Handle(method, pattern string, handler HandlerFunc) {
	rt.routes = append(rt.routes, Route{
		Method:  strings.ToUpper(method),
		Pattern: pattern,
		Handler: handler,
	})
	log.Printf("[ROUTER] Register: %s %s", strings.ToUpper(method), pattern)
}

// GET shortcut untuk Handle("GET", ...)
func (rt *Router) GET(pattern string, handler HandlerFunc) {
	rt.Handle("GET", pattern, handler)
}

// POST shortcut untuk Handle("POST", ...)
func (rt *Router) POST(pattern string, handler HandlerFunc) {
	rt.Handle("POST", pattern, handler)
}

// PUT shortcut untuk Handle("PUT", ...)
func (rt *Router) PUT(pattern string, handler HandlerFunc) {
	rt.Handle("PUT", pattern, handler)
}

// DELETE shortcut untuk Handle("DELETE", ...)
func (rt *Router) DELETE(pattern string, handler HandlerFunc) {
	rt.Handle("DELETE", pattern, handler)
}

// ServeHTTP mengimplementasikan http.Handler.
// Melakukan matching pattern, method check, dan param extraction.
func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	for _, route := range rt.routes {
		params, ok := matchPattern(route.Pattern, path)
		if !ok {
			continue
		}

		// Method check
		if r.Method != route.Method {
			// Jika path cocok tapi method berbeda, lanjut cari route lain
			// yang mungkin handle method berbeda untuk path yang sama
			continue
		}

		route.Handler(w, r, params)
		return
	}

	// Cek apakah path ada tapi method tidak sesuai
	pathFound := false
	for _, route := range rt.routes {
		if _, ok := matchPattern(route.Pattern, path); ok {
			pathFound = true
			break
		}
	}

	if pathFound {
		Error(w, http.StatusMethodNotAllowed, "Method tidak diizinkan")
		return
	}

	NotFound(w, "Endpoint tidak ditemukan")
}

// matchPattern mencocokkan URL path dengan pattern dan mengekstrak params.
//
// Aturan matching:
//   - Segmen literal harus sama persis
//   - Segmen {param} menerima nilai apapun dan dikumpulkan ke params slice
//
// Contoh:
//
//	pattern: /api/v1/nodes/{id}
//	path:    /api/v1/nodes/42
//	→ params = ["42"], ok = true
//
//	pattern: /api/v1/backends/{id}/servers/{sid}
//	path:    /api/v1/backends/3/servers/7
//	→ params = ["3", "7"], ok = true
func matchPattern(pattern, path string) ([]string, bool) {
	patParts := splitPath(pattern)
	pathParts := splitPath(path)

	if len(patParts) != len(pathParts) {
		return nil, false
	}

	params := make([]string, 0)
	for i, pat := range patParts {
		if strings.HasPrefix(pat, "{") && strings.HasSuffix(pat, "}") {
			// parameter segment — terima nilai apapun
			params = append(params, pathParts[i])
		} else if pat != pathParts[i] {
			return nil, false
		}
	}
	return params, true
}

// splitPath memisahkan path menjadi segmen, mengabaikan slash awal/akhir
func splitPath(path string) []string {
	path = strings.Trim(path, "/")
	if path == "" {
		return []string{}
	}
	return strings.Split(path, "/")
}
