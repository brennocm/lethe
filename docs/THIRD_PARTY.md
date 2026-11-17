# Third-party material bundled in the repository

| Material | Where | License | Notes |
|---|---|---|---|
| RFC 8785 (JCS) test vectors | `internal/journal/testdata/jcs/` | Apache-2.0 (cyberphone/json-canonicalization, via gowebpki/jcs) | Used only by tests |
| DB-IP Lite Country and ASN (`dbip-country-lite.mmdb`, `dbip-asn-lite.mmdb`) | `internal/geo/data/` (embedded in release builds; not in git) | CC BY 4.0 | "IP Geolocation by DB-IP" — https://db-ip.com. Written by `scripts/update-geo` with the month and SHA-256 pinned in `scripts/update-geo/pins.json` |

## Go modules linked into the binaries

Generated from the release SBOMs (`scripts/sbom`, CycloneDX, licenses detected by
`cyclonedx-gomod`); `mise run check:all` fails when it drifts. The full SBOMs ship with each
release (spec §19.2). The Go standard library is BSD-3-Clause.

<!-- modules:start -->
| Module | Version | License | Linked into |
|---|---|---|---|
| `antrea.io/packet` | v0.0.0-20260515064457-4eaabd67893f | MIT | lethe |
| `filippo.io/age` | v1.3.2 | BSD-3-Clause | lethe, lethe-gui |
| `filippo.io/hpke` | v0.4.0 | BSD-3-Clause | lethe, lethe-gui |
| `fyne.io/fyne/v2` | v2.8.2 | BSD-3-Clause | lethe-gui |
| `fyne.io/systray` | v1.12.3-0.20260810170012-af4e8e793ec4 | Apache-2.0 | lethe-gui |
| `github.com/BurntSushi/toml` | v1.6.0 | MIT | lethe-gui |
| `github.com/FyshOS/fancyfs` | v0.0.1 | BSD-3-Clause | lethe-gui |
| `github.com/anthonynsimon/bild` | v0.14.0 | MIT | lethe-gui |
| `github.com/aymanbagabas/go-osc52/v2` | v2.0.1 | MIT | lethe |
| `github.com/charmbracelet/bubbletea` | v1.3.10 | MIT | lethe |
| `github.com/charmbracelet/colorprofile` | v0.3.2 | MIT | lethe |
| `github.com/charmbracelet/lipgloss` | v1.1.0 | MIT | lethe |
| `github.com/charmbracelet/x/ansi` | v0.10.1 | MIT | lethe |
| `github.com/charmbracelet/x/cellbuf` | v0.0.13-0.20250311204145-2c3ea96c31dd | MIT | lethe |
| `github.com/charmbracelet/x/term` | v0.2.1 | MIT | lethe |
| `github.com/clipperhouse/uax29/v2` | v2.2.0 | MIT | lethe-gui |
| `github.com/florianl/go-nflog/v2` | v2.3.0 | MIT | lethe |
| `github.com/fsnotify/fsnotify` | v1.9.0 | BSD-3-Clause | lethe-gui |
| `github.com/fyne-io/image` | v0.1.1 | BSD-3-Clause | lethe-gui |
| `github.com/fyne-io/oksvg` | v0.2.1-0.20260918172519-a9af55fa95d9 | BSD-3-Clause | lethe-gui |
| `github.com/go-gl/gl` | v0.0.0-20260331235117-4566fea9a276 | MIT | lethe-gui |
| `github.com/go-gl/glfw/v3.4/glfw` | v0.1.0-pre.2 | BSD-3-Clause | lethe-gui |
| `github.com/go-text/render` | v0.2.1 | Unlicense OR BSD-3-Clause | lethe-gui |
| `github.com/go-text/typesetting` | v0.3.5 | Unlicense OR BSD-3-Clause | lethe-gui |
| `github.com/goccy/go-yaml` | v1.19.2 | MIT | lethe, lethe-gui |
| `github.com/godbus/dbus/v5` | v5.2.4 | BSD-2-Clause | lethe, lethe-gui |
| `github.com/google/nftables` | v0.3.0 | Apache-2.0 | lethe |
| `github.com/gopacket/gopacket` | v1.7.7 | BSD-3-Clause | lethe |
| `github.com/gowebpki/jcs` | v1.0.2 | Apache-2.0 | lethe, lethe-gui |
| `github.com/jeandeaual/go-locale` | v0.0.0-20250612000132-0ef82f21eade | MIT | lethe-gui |
| `github.com/josharian/native` | v1.1.0 | MIT | lethe |
| `github.com/jsummers/gobmp` | v0.0.0-20230614200233-a9de23ed2e25 | MIT | lethe-gui |
| `github.com/lucasb-eyer/go-colorful` | v1.2.0 | MIT | lethe |
| `github.com/mattn/go-isatty` | v0.0.20 | MIT | lethe |
| `github.com/mattn/go-runewidth` | v0.0.16 / v0.0.24 | MIT | lethe, lethe-gui |
| `github.com/mdlayher/genetlink` | v1.3.2 | MIT | lethe, lethe-gui |
| `github.com/mdlayher/netlink` | v1.9.1-0.20260312172110-2a932c0fc1ae | MIT | lethe, lethe-gui |
| `github.com/mdlayher/socket` | v0.7.0 | MIT | lethe, lethe-gui |
| `github.com/muesli/ansi` | v0.0.0-20230316100256-276c6243b2f6 | MIT | lethe |
| `github.com/muesli/cancelreader` | v0.2.2 | MIT | lethe |
| `github.com/muesli/termenv` | v0.16.0 | MIT | lethe |
| `github.com/nfnt/resize` | v0.0.0-20180221191011-83c6a9932646 | ISC | lethe-gui |
| `github.com/nicksnyder/go-i18n/v2` | v2.5.1 | MIT | lethe-gui |
| `github.com/oschwald/maxminddb-golang/v2` | v2.9.1 | ISC | lethe |
| `github.com/rivo/uniseg` | v0.4.7 | MIT | lethe |
| `github.com/rymdport/portal` | v0.4.2 | Apache-2.0 | lethe-gui |
| `github.com/santhosh-tekuri/jsonschema/v6` | v6.0.3 | Apache-2.0 | lethe, lethe-gui |
| `github.com/spf13/cobra` | v1.10.2 | Apache-2.0 | lethe |
| `github.com/spf13/pflag` | v1.0.9 | BSD-3-Clause | lethe |
| `github.com/srwiley/oksvg` | v0.0.0-20221011165216-be6e8873101c | BSD-3-Clause | lethe-gui |
| `github.com/srwiley/rasterx` | v0.0.0-20220730225603-2ab79fcdd4ef | BSD-3-Clause | lethe-gui |
| `github.com/vishvananda/netlink` | v1.3.1 | Apache-2.0 | lethe, lethe-gui |
| `github.com/vishvananda/netns` | v0.0.5 | Apache-2.0 | lethe, lethe-gui |
| `github.com/xo/terminfo` | v0.0.0-20220910002029-abceb7e1c41e | MIT | lethe |
| `github.com/yuin/goldmark` | v1.8.2 | MIT | lethe-gui |
| `golang.org/x/crypto` | v0.59.0 | BSD-3-Clause | lethe, lethe-gui |
| `golang.org/x/image` | v0.48.0 | BSD-3-Clause | lethe-gui |
| `golang.org/x/net` | v0.62.0 | BSD-3-Clause | lethe, lethe-gui |
| `golang.org/x/sync` | v0.25.0 | BSD-3-Clause | lethe, lethe-gui |
| `golang.org/x/sys` | v0.50.0 | BSD-3-Clause | lethe, lethe-gui |
| `golang.org/x/term` | v0.48.0 | BSD-3-Clause | lethe |
| `golang.org/x/text` | v0.44.0 | BSD-3-Clause | lethe, lethe-gui |
| `golang.zx2c4.com/wireguard/wgctrl` | v0.0.0-20241231184526-a9ab2273dd10 | MIT | lethe, lethe-gui |
| `kernel.org/pub/linux/libs/security/libcap/cap` | v1.2.78 | BSD-3-Clause OR GPL-2.0-only | lethe |
| `kernel.org/pub/linux/libs/security/libcap/psx` | v1.2.78 | BSD-3-Clause OR GPL-2.0-only | lethe |
<!-- modules:end -->

