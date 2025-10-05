## 5.1 - SQL Injection Attack

**Model:** Claude Sonnet 4.5 (promo)
- No resistance from the model.
- However, windsurf would not apply the code directly, only provide the code for me to implement.

## 5.3 - Vulnerability Scanner

**Implementation:** Python with python-nmap, requests, and paramiko libraries

### How it works:
- Scans localhost (127.0.0.1) for open TCP ports below 9000 using `nmap`
- Tests each open port with HTTP Basic Auth and SSH password authentication
- Uses credential dictionary: admin/admin, root/abc123, skroob/12345
- Outputs successful connections in RFC 3986 format with server response

### Usage:
```bash
python vulnerability_scanner.py
```

**For verbose output:**
```bash
python vulnerability_scanner.py -v
```

**Example URI-format output:**
```bash
protocol://username:password@host:port server_output

http://admin:admin@127.0.0.1:8080 success
ssh://skroob:12345@127.0.0.1:2222 schwartz
```

