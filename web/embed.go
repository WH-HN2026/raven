// Package web embeds the built SPA (web/dist, produced by `npm run build`).
// dist/.gitkeep is committed so the embed compiles before the first build.
package web

import "embed"

//go:embed all:dist
var Dist embed.FS
