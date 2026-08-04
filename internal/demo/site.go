// Copyright 2026 The Resiliency Wreath Authors
// SPDX-License-Identifier: Apache-2.0

package demo

import (
	"fmt"
	"strings"
	"time"
)

// Accent hues follow the dashboard's categorical order (slot i =
// member i), so a member keeps one identity color across its own page,
// its card, and the health matrix.
var accents = []string{
	"#2a78d6", "#eb6834", "#1baf7a", "#eda100",
	"#e87ba4", "#008300", "#4a3aa7", "#e34948",
}

var orgPatterns = []string{
	"Town of %s", "%s County", "City of %s", "%s Public Library",
	"%s Water District", "Port of %s", "%s Unified Schools", "%s Parks District",
}

// servers is the web-server software each member's origin "runs" —
// pure labeling, but it makes the co-tenancy visible: the origin is
// whatever ordinary server the member already operates, and the wreath
// agent is a separate daemon beside it.
var servers = []string{
	"nginx", "httpd", "IIS", "Caddy", "lighttpd", "obhttpd", "Traefik", "thttpd",
}

func serverName(slot int) string { return servers[slot%len(servers)] }

// notices cycle with the published version so an update is visible the
// moment it lands in an iframe.
var notices = []string{
	"All services operating normally.",
	"Scheduled maintenance tonight, 10 pm to midnight.",
	"Boil-water advisory lifted for the north district.",
	"Council meeting moved to Thursday, 7 pm.",
	"Storm-debris pickup continues through Friday.",
}

func orgName(id string, slot int) string {
	return fmt.Sprintf(orgPatterns[slot%len(orgPatterns)], titleCase(id))
}

func titleCase(id string) string {
	words := strings.FieldsFunc(id, func(r rune) bool { return r == '-' || r == '_' })
	for i, w := range words {
		words[i] = strings.ToUpper(w[:1]) + w[1:]
	}
	return strings.Join(words, " ")
}

// siteFiles builds one member's whole site: a single self-contained
// lights-on page (tiny, static, JS-free — the DESIGN §2 cellular-link
// constraint), stamped with its bundle version.
func siteFiles(id string, version uint64, slot int, now time.Time) map[string]string {
	page := strings.NewReplacer(
		"{{ORG}}", orgName(id, slot),
		"{{ACCENT}}", accents[slot%len(accents)],
		"{{NOTICE}}", notices[int((version-1))%len(notices)],
		"{{VERSION}}", fmt.Sprintf("%d", version),
		"{{PUB}}", now.Format("Jan 2, 15:04:05"),
		"{{ID}}", id,
	).Replace(pageTemplate)
	return map[string]string{"index.html": page}
}

const pageTemplate = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ORG}} — status</title>
<style>
  body { margin:0; font:15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
         color:#0b0b0b; background:#f9f9f7; }
  .band { height:8px; background:{{ACCENT}}; }
  main { max-width:34rem; margin:0 auto; padding:1.1rem 1.4rem; }
  h1 { font-size:1.3rem; margin:.2rem 0 .1rem; }
  .tag { color:#52514e; font-size:.85rem; margin-bottom:.9rem; }
  .tag b { color:#0b0b0b; }
  .status { border:1px solid rgba(11,11,11,.10); background:#fcfcfb;
            border-radius:8px; padding:.8rem 1rem; margin:.8rem 0; }
  .ok { font-weight:600; }
  .ok::before { content:"✓ "; color:#0ca30c; }
  .notice { margin:.35rem 0 0; }
  dl { display:grid; grid-template-columns:auto 1fr; gap:.15rem .8rem;
       font-size:.9rem; margin:1rem 0; }
  dt { color:#52514e; }
  dd { margin:0; }
  footer { font-size:.78rem; color:#898781; border-top:1px solid #e1e0d9;
           padding-top:.7rem; margin-top:1.1rem; }
</style>
</head><body>
<div class="band"></div>
<main>
  <h1>{{ORG}}</h1>
  <div class="tag">Official status page · signed bundle <b>v{{VERSION}}</b></div>
  <div class="status">
    <div class="ok">We are here — lights on</div>
    <p class="notice">{{NOTICE}}</p>
  </div>
  <dl>
    <dt>Phone</dt><dd>(555) 010-0199</dd>
    <dt>Email</dt><dd>hello@{{ID}}.example</dd>
    <dt>In person</dt><dd>Mon–Fri, 9 am–4:30 pm</dd>
  </dl>
  <footer>Published {{PUB}} · Ed25519-signed by {{ORG}}.
  Wreath peers can relay this page but cannot alter it.</footer>
</main>
</body></html>
`
