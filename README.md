# Railway HTTP/HTTPS Forward Proxy

A lightweight forward proxy with authentication, HTTPS CONNECT tunneling, IP allowlisting, and logging.

## Deploy to Railway

1. Push this repo to GitHub
2. Go to [railway.app](https://railway.app) → New Project → Deploy from GitHub repo
3. Set these environment variables in Railway dashboard:

| Variable      | Description                                      |
|---------------|--------------------------------------------------|
| PROXY_USER    | Username for proxy auth                          |
| PROXY_PASS    | Password for proxy auth                          |
| IP_ALLOWLIST  | Comma-separated IPs (leave empty to allow all)   |
| NODE_ENV      | Set to `production`                              |

4. Go to Settings → Networking → Generate Domain
5. Railway sets PORT automatically

## Client Usage

### curl
```bash
# HTTP
curl -x http://admin:changeme@your-app.up.railway.app:443 http://example.com

# HTTPS
curl -x http://admin:changeme@your-app.up.railway.app:443 https://example.com
```

### Environment variables
```bash
export HTTP_PROXY=http://admin:changeme@your-app.up.railway.app:443
export HTTPS_PROXY=http://admin:changeme@your-app.up.railway.app:443
export NO_PROXY=localhost,127.0.0.1
```

### Python
```python
import requests
proxies = {
    "http":  "http://admin:changeme@your-app.up.railway.app:443",
    "https": "http://admin:changeme@your-app.up.railway.app:443",
}
r = requests.get("https://example.com", proxies=proxies)
```

### Node.js
```js
const { ProxyAgent, fetch } = require("undici");
const dispatcher = new ProxyAgent("http://admin:changeme@your-app.up.railway.app:443");
const res = await fetch("https://example.com", { dispatcher });
```

## Local Testing
```bash
cp .env.example .env
npm install
node index.js
```
