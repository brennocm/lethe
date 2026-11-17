# Embedded geo data

`scripts/update-geo` writes here, at release time, the two DB-IP Lite databases:

- `dbip-country-lite.mmdb`
- `dbip-asn-lite.mmdb`

DB-IP Lite is licensed CC BY 4.0 (attribution in `docs/THIRD_PARTY.md`). The files are not in
the repository: a build without them reports "no geo database" and TUN-006, the country part of
NET-011 and PER-001 stay inactive instead of guessing.
