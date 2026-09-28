# Usage Notes

This project does **not** send network traffic. It analyzes files you provide.

## Prepare a Capture

Using `curl` (authorized target only):
```bash
curl -I -sD - -o /dev/null https://example.com > examples/sample_headers.txt
```

Export a HAR from your browser (DevTools > Network > Save all as HAR with content), then:
```bash
edgeprint analyze -i path/to/export.har --format har
```

Provide JSON observations (example schema):
```json
{
  "url": "https://example.com/",
  "method": "GET",
  "status_code": 200,
  "headers": {
    "server": "cloudflare",
    "cf-ray": "123",
    "set-cookie": "__cfduid=..."
  },
  "body_excerpt": "..."  // optional
}
```

Run the analyzer:
```bash
edgeprint analyze -i examples/sample_headers.txt --format raw
edgeprint analyze -i observation.json --format json --json
```

Analyze a whole capture - every HAR entry, or a directory of files in mixed formats:
```bash
edgeprint analyze -i path/to/export.har
edgeprint analyze -i captures/ extra/response.txt --json
edgeprint analyze -i a.txt -i b.txt            # -i may repeat
```

With more than one response the output is a per-host summary. Folding rules:

- a host is WAF-likely if any of its responses is;
- per-layer confidence is the maximum over the host's responses, not a sum;
- vendors are shown with the number of responses naming them, e.g. `[4/4]`;
- responses with no URL (raw dumps) are grouped by file;
- hidden files and directories under a directory input are ignored;
- inputs that cannot be read or parsed, and responses with no headers (a stray
  README in a capture directory), are reported under `skipped` rather than
  counted as clean hosts, and do not abort the run. A single explicitly named
  file that fails still exits 1.

`--format` applies to every input; the default detects it per file by extension
(`.har`, `.json`, anything else raw).

Exit codes are described in the README. Across several responses the most severe
host decides: 2 if any host is WAF-likely, else 3 if any shows an edge, else 0,
and 1 only if no response carried headers at all.
