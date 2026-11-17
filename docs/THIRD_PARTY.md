# Third-party material bundled in the repository

| Material | Where | License | Notes |
|---|---|---|---|
| RFC 8785 (JCS) test vectors | `internal/journal/testdata/jcs/` | Apache-2.0 (cyberphone/json-canonicalization, via gowebpki/jcs) | Used only by tests |
| DB-IP Lite Country and ASN (`dbip-country-lite.mmdb`, `dbip-asn-lite.mmdb`) | `internal/geo/data/` (embedded in release builds; not in git) | CC BY 4.0 | "IP Geolocation by DB-IP" — https://db-ip.com. Written by `scripts/update-geo` with the month and SHA-256 pinned in `scripts/update-geo/pins.json` |

Go module dependencies are listed in `go.mod`; their licenses ship in the release SBOM (spec §19.2).
