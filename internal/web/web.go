package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed index.html style.css script.js
var content embed.FS

func GetHandler() (http.Handler, error) {
	fs, err := fs.Sub(content, ".")
	if err != nil {
		return nil, err
	}
	return http.FileServer(http.FS(fs)), nil
}