package core

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ParseJSON mengurai body JSON ke dalam target struct.
// Mengembalikan error jika body tidak valid JSON.
func ParseJSON(r *http.Request, target interface{}) error {
	if r.Body == nil {
		return fmt.Errorf("request body kosong")
	}
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return fmt.Errorf("body tidak valid: %v", err)
	}
	return nil
}

// RequireMethod memeriksa apakah HTTP method sesuai.
// Menulis 405 dan mengembalikan false jika tidak sesuai.
func RequireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		w.Header().Set("Allow", method)
		Error(w, http.StatusMethodNotAllowed, fmt.Sprintf("Method %s tidak diizinkan", r.Method))
		return false
	}
	return true
}

// RequireMethods memeriksa apakah HTTP method termasuk salah satu yang diizinkan.
func RequireMethods(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	for _, m := range methods {
		if r.Method == m {
			return true
		}
	}
	w.Header().Set("Allow", joinStrings(methods, ", "))
	Error(w, http.StatusMethodNotAllowed, fmt.Sprintf("Method %s tidak diizinkan", r.Method))
	return false
}

func joinStrings(ss []string, sep string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}
