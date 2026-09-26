package handler

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// UploadFileServer melayani file dari uploadDir di bawah prefix URL /upload/.
//
// Aturan:
//   - Directory listing dinonaktifkan — akses ke direktori menghasilkan 403.
//   - Symlink di dalam uploadDir diikuti (target boleh di luar uploadDir).
//   - Path traversal via "../" diblokir — path di luar uploadDir menghasilkan 403.
//   - Content-Type, ETag, Last-Modified, dan Range request ditangani otomatis.
func UploadFileServer(uploadDir string) http.Handler {
	// Resolve absolute path sekali saat startup agar perbandingan konsisten.
	absUpload, _ := filepath.Abs(uploadDir)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ambil path setelah prefix /upload
		urlPath := strings.TrimPrefix(r.URL.Path, "/upload")
		if urlPath == "" || urlPath == "/" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Bersihkan path dan gabung dengan upload dir
		fullPath := filepath.Join(absUpload, filepath.FromSlash(filepath.Clean("/"+urlPath)))

		// Blokir path traversal: path hasil join harus tetap di dalam absUpload
		if !strings.HasPrefix(fullPath, absUpload+string(filepath.Separator)) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Buka file — os.Open mengikuti symlink secara default
		f, err := os.Open(fullPath)
		if err != nil {
			if os.IsNotExist(err) {
				http.NotFound(w, r)
			} else {
				http.Error(w, "Forbidden", http.StatusForbidden)
			}
			return
		}
		defer f.Close()

		fi, err := f.Stat()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Blokir akses ke direktori
		if fi.IsDir() {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// ServeContent: Content-Type dari ekstensi, ETag, Last-Modified, Range
		http.ServeContent(w, r, fi.Name(), fi.ModTime(), f)
	})
}
