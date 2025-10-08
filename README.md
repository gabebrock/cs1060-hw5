# CS1060 - HW5

**Instructions for running the code:** 
- Create a virtual environment: `python -m venv venv`
- Activate the virtual environment: `source venv/bin/activate` (Linux/Mac) or `venv\Scripts\activate` (Windows)
- Install dependencies: `pip install -r requirements.txt`

**Submission Files:**
- `./attack.json` - SQL injection attack file
- `./test.json` - Test suite file
- `./prompts.txt` - Prompts documentation
- `./vulnerability_scanner.py` - Vulnerability scanner file
    - `./test_scanner.py` - Test suite file for protocol scanner
- `./requirements.txt` - Dependencies file
- `./README.md` - README file
- `./.gitignore` - Git ignore file (namely excluding virtual environment `/hw5-env`)

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

##### Test Suite:
```bash
python test_scanner.py
```
