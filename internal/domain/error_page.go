package domain

import (
	"fmt"
	"time"
)

// ErrorPage menyimpan custom HTML untuk satu HTTP error code
type ErrorPage struct {
	ID        int       `json:"id_error_pages"`
	ErrorCode int       `json:"error_code"`
	Content   string    `json:"content"`
	Enabled   bool      `json:"enabled"`
	Created   time.Time `json:"created"`
	Timestamp time.Time `json:"timestamp"`
}

// ErrorCodeInfo adalah metadata untuk satu HTTP error code
type ErrorCodeInfo struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// SupportedErrorCodes adalah daftar HTTP error code yang didukung HAProxy errorfile
var SupportedErrorCodes = []ErrorCodeInfo{
	{Code: 400, Message: "Bad Request"},
	{Code: 403, Message: "Forbidden"},
	{Code: 404, Message: "Not Found"},
	{Code: 408, Message: "Request Timeout"},
	{Code: 500, Message: "Internal Server Error"},
	{Code: 502, Message: "Bad Gateway"},
	{Code: 503, Message: "Service Unavailable"},
	{Code: 504, Message: "Gateway Timeout"},
}

// GetErrorCodeInfo mengembalikan ErrorCodeInfo untuk code tertentu, atau default jika tidak ditemukan
func GetErrorCodeInfo(code int) ErrorCodeInfo {
	for _, info := range SupportedErrorCodes {
		if info.Code == code {
			return info
		}
	}
	return ErrorCodeInfo{Code: code, Message: "Error"}
}

// WrapHTTPResponse membungkus raw HTML dengan HTTP response headers sesuai format HAProxy errorfile.
// HAProxy errorfile membutuhkan HTTP/1.0 response headers diikuti blank line lalu body.
func WrapHTTPResponse(code int, statusMessage, html string) string {
	return fmt.Sprintf(
		"HTTP/1.0 %d %s\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\n\r\n%s",
		code, statusMessage, len([]byte(html)), html,
	)
}

// DefaultHTML mengembalikan halaman error HTML berbranding HAPM/Indonetsoft untuk kode tertentu.
// Digunakan sebagai fallback ketika fitur Custom Error Pages tidak aktif atau halaman belum dikustomisasi.
func DefaultHTML(code int, message string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%d %s</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#080d19;color:#e2e8f0;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:32px}
.glow{position:fixed;top:-200px;left:50%%;transform:translateX(-50%%);width:700px;height:500px;background:radial-gradient(ellipse,rgba(59,130,246,.18) 0%%,transparent 70%%);pointer-events:none}
.card{position:relative;background:rgba(15,23,42,.8);border:1px solid rgba(59,130,246,.2);border-radius:20px;padding:52px 48px;text-align:center;max-width:520px;width:100%%;backdrop-filter:blur(16px);box-shadow:0 0 60px rgba(0,0,0,.5)}
.badge{display:inline-flex;align-items:center;gap:6px;background:rgba(59,130,246,.12);border:1px solid rgba(59,130,246,.3);color:#60a5fa;border-radius:999px;padding:4px 14px;font-size:12px;font-weight:500;letter-spacing:.5px;margin-bottom:28px}
.dot{width:6px;height:6px;background:#3b82f6;border-radius:50%%;animation:pulse 2s infinite}
@keyframes pulse{0%%,100%%{opacity:1}50%%{opacity:.3}}
.code{font-size:100px;font-weight:900;line-height:1;background:linear-gradient(135deg,#60a5fa,#a78bfa);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;letter-spacing:-4px}
.divider{width:40px;height:2px;background:linear-gradient(90deg,transparent,#3b82f6,transparent);margin:20px auto}
.title{font-size:20px;font-weight:600;color:#f1f5f9;margin-bottom:10px}
.desc{font-size:14px;color:#64748b;line-height:1.8;max-width:360px;margin:0 auto}
.actions{margin-top:32px}
.btn{display:inline-flex;align-items:center;gap:8px;background:rgba(59,130,246,.15);border:1px solid rgba(59,130,246,.35);color:#93c5fd;padding:10px 22px;border-radius:10px;font-size:13px;text-decoration:none;transition:all .2s;cursor:pointer}
.btn:hover{background:rgba(59,130,246,.25);border-color:#3b82f6;color:#bfdbfe}
.brand{margin-top:40px;font-size:11px;color:#1e3a5f;display:flex;align-items:center;justify-content:center;gap:8px}
.brand a{color:#1d4ed8;text-decoration:none;transition:color .2s}
.brand a:hover{color:#3b82f6}
.sep{color:#1e3a5f}
</style>
</head>
<body>
<div class="glow"></div>
<div class="card">
  <div class="badge"><span class="dot"></span> SERVICE ERROR</div>
  <div class="code">%d</div>
  <div class="divider"></div>
  <div class="title">%s</div>
  <div class="desc">We&rsquo;re sorry, but something went wrong on our end.<br>Please try again in a moment.</div>
  <div class="actions">
    <a href="javascript:history.back()" class="btn">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 18 9 12 15 6"></polyline></svg>
      Go Back
    </a>
  </div>
  <div class="brand">
    <a href="https://github.com/aefw/hapm" target="_blank">HAPM</a>
    <span class="sep">&bull;</span>
    <a href="https://indonetsoft.com" target="_blank">indonetsoft.com</a>
  </div>
</div>
</body>
</html>`, code, message, code, message)
}
