
**Check Header Info**
- Request Headers: Lines prefixed with > represent the headers sent in the HTTP request.
- Response Headers: Lines prefixed with < represent the headers received in the HTTP response.

```bash
# -v: It includes details about the connection, request headers, response headers, and other debugging information.
# -s: silent
curl -s -v 10.10.11.208 1>/dev/null

# use domain name
curl -s -v searcher.htb 1>/dev/null
```

