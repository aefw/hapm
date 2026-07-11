package core

import (
	"encoding/json"
	"net/http"
)

// Response adalah struktur standar JSON response HAPM.
// Konsisten di seluruh endpoint.
type Response struct {
	Status  bool        `json:"status"`
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Datas   interface{} `json:"datas,omitempty"`
}

// JSON menulis response JSON ke http.ResponseWriter
func JSON(w http.ResponseWriter, code int, status bool, message string, data interface{}, datas interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(Response{
		Status:  status,
		Code:    code,
		Message: message,
		Data:    data,
		Datas:   datas,
	})
}

// Success response 200 OK dengan single data object
func Success(w http.ResponseWriter, message string, data interface{}) {
	JSON(w, http.StatusOK, true, message, data, nil)
}

// SuccessList response 200 OK dengan array data
func SuccessList(w http.ResponseWriter, message string, datas interface{}) {
	JSON(w, http.StatusOK, true, message, nil, datas)
}

// Created response 201 Created
func Created(w http.ResponseWriter, message string, data interface{}) {
	JSON(w, http.StatusCreated, true, message, data, nil)
}

// Error response dengan code dan message kustom
func Error(w http.ResponseWriter, code int, message string) {
	JSON(w, code, false, message, nil, nil)
}

// BadRequest response 400
func BadRequest(w http.ResponseWriter, message string) {
	Error(w, http.StatusBadRequest, message)
}

// Unauthorized response 401
func Unauthorized(w http.ResponseWriter, message string) {
	Error(w, http.StatusUnauthorized, message)
}

// Forbidden response 403
func Forbidden(w http.ResponseWriter, message string) {
	Error(w, http.StatusForbidden, message)
}

// NotFound response 404
func NotFound(w http.ResponseWriter, message string) {
	Error(w, http.StatusNotFound, message)
}

// Conflict response 409
func Conflict(w http.ResponseWriter, message string) {
	Error(w, http.StatusConflict, message)
}

// TooManyRequests response 429
func TooManyRequests(w http.ResponseWriter, message string) {
	Error(w, http.StatusTooManyRequests, message)
}

// InternalError response 500.
// Tidak mengirim detail error ke client untuk mencegah information leakage.
// Log error di server side sebelum memanggil fungsi ini.
func InternalError(w http.ResponseWriter, _ string) {
	Error(w, http.StatusInternalServerError, "Terjadi kesalahan internal, silakan coba lagi")
}
