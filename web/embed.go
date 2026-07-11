package web

import "embed"

// FS berisi semua file frontend yang sudah dibuild (di web/dist/).
// Di-embed ke dalam binary supaya Docker scratch image bisa serve frontend.
//
//go:embed all:dist
var FS embed.FS
