const http = require("http");
const net = require("net");

const PORT = process.env.PORT || 8080;
const PROXY_USER = process.env.PROXY_USER || "admin";
const PROXY_PASS = process.env.PROXY_PASS || "changeme";
const IP_ALLOWLIST = process.env.IP_ALLOWLIST || "";

// ─── IP / CIDR helpers ────────────────────────────────────────────────────────

function ipToLong(ip) {
  return ip.split(".").reduce(function (acc, octet) {
    return (acc << 8) + parseInt(octet, 10);
  }, 0) >>> 0;
}

function isValidIPv4(ip) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) &&
    ip.split(".").every(function (o) { return parseInt(o, 10) <= 255; });
}

function isCIDR(entry) {
  return entry.indexOf("/") !== -1;
}

function ipMatchesCIDR(ip, cidr) {
  var parts = cidr.split("/");
  var base = parts[0];
  var prefix = parseInt(parts[1], 10);

  if (!isValidIPv4(base) || !isValidIPv4(ip) || isNaN(prefix) || prefix < 0 || prefix > 32) {
    return false;
  }

  var mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return (ipToLong(ip) & mask) === (ipToLong(base) & mask);
}

function parseAllowlist(raw) {
  if (!raw || !raw.trim()) return [];
  return raw.split(",").map(function (entry) { return entry.trim(); }).filter(Boolean);
}

var allowedEntries = parseAllowlist(IP_ALLOWLIST);

function isIPAllowed(ip) {
  if (allowedEntries.length === 0) return true;

  // Strip IPv6-mapped IPv4 prefix (e.g. ::ffff:1.2.3.4 → 1.2.3.4)
  var clean = ip.replace(/^::ffff:/, "");

  for (var i = 0; i < allowedEntries.length; i++) {
    var entry = allowedEntries[i];
    if (isCIDR(entry)) {
      if (ipMatchesCIDR(clean, entry)) return true;
    } else {
      if (clean === entry) return true;
    }
  }
  return false;
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

function checkAuth(req) {
  var header = req.headers["proxy-authorization"] || "";
  if (!header.startsWith("Basic ")) return false;
  var decoded = Buffer.from(header.slice(6), "base64").toString("utf8");
  var colon = decoded.indexOf(":");
  if (colon === -1) return false;
  return decoded.slice(0, colon) === PROXY_USER && decoded.slice(colon + 1) === PROXY_PASS;
}

// ─── Responses ────────────────────────────────────────────────────────────────

function denyAuth(res) {
  res.writeHead(407, {
    "Proxy-Authenticate": 'Basic realm="Proxy"',
    "Content-Type": "text/plain"
  });
  res.end("Proxy authentication required");
}

function denyIP(res) {
  res.writeHead(403, { "Content-Type": "text/plain" });
  res.end("Forbidden: IP not allowed");
}

// ─── Logging ──────────────────────────────────────────────────────────────────

function log(type, ip, method, url, extra) {
  var ts = new Date().toISOString();
  var line = "[" + ts + "] " + type + " " + ip + " " + method + " " + url +
    (extra ? " | " + extra : "");
  console.log(line);
}

// ─── HTTP forward proxy ───────────────────────────────────────────────────────

var server = http.createServer(function (req, res) {
  // Health check for Railway / load balancers
  if (req.method === "GET" && req.url === "/" && !req.headers["proxy-authorization"]) {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("OK");
    return;
  }

  var clientIP = (req.socket.remoteAddress || "").replace(/^::ffff:/, "");

  if (!isIPAllowed(clientIP)) {
    log("DENY_IP", clientIP, req.method, req.url);
    return denyIP(res);
  }

  if (!checkAuth(req)) {
    log("DENY_AUTH", clientIP, req.method, req.url);
    return denyAuth(res);
  }

  log("HTTP", clientIP, req.method, req.url);

  var parsed;
  try {
    parsed = new URL(req.url);
  } catch (e) {
    res.writeHead(400, { "Content-Type": "text/plain" });
    res.end("Bad Request: invalid URL");
    return;
  }

  var headers = Object.assign({}, req.headers);
  delete headers["proxy-authorization"];

  var options = {
    hostname: parsed.hostname,
    port: parsed.port || 80,
    path: parsed.pathname + parsed.search,
    method: req.method,
    headers: headers
  };

  var proxyReq = http.request(options, function (proxyRes) {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  });

  proxyReq.on("error", function (err) {
    log("ERR", clientIP, req.method, req.url, err.message);
    if (!res.headersSent) {
      res.writeHead(502, { "Content-Type": "text/plain" });
    }
    res.end("Bad Gateway: " + err.message);
  });

  req.pipe(proxyReq);
});

// ─── HTTPS CONNECT tunnel ─────────────────────────────────────────────────────

server.on("connect", function (req, clientSocket, head) {
  var clientIP = (clientSocket.remoteAddress || "").replace(/^::ffff:/, "");

  if (!isIPAllowed(clientIP)) {
    log("DENY_IP", clientIP, "CONNECT", req.url);
    clientSocket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
    return clientSocket.destroy();
  }

  if (!checkAuth(req)) {
    log("DENY_AUTH", clientIP, "CONNECT", req.url);
    clientSocket.write(
      "HTTP/1.1 407 Proxy Authentication Required\r\n" +
      "Proxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n"
    );
    return clientSocket.destroy();
  }

  var parts = req.url.split(":");
  var host = parts[0];
  var port = parseInt(parts[1], 10) || 443;

  log("CONNECT", clientIP, "CONNECT", host + ":" + port);

  var serverSocket = net.connect(port, host, function () {
    log("TUNNEL", clientIP, "CONNECT", host + ":" + port, "established");
    clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (head && head.length > 0) serverSocket.write(head);
    serverSocket.pipe(clientSocket);
    clientSocket.pipe(serverSocket);
  });

  serverSocket.on("error", function (err) {
    log("SERVER_ERR", clientIP, "CONNECT", req.url, err.message);
    clientSocket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n");
    clientSocket.destroy();
  });

  clientSocket.on("error", function (err) {
    log("CLIENT_ERR", clientIP, "CONNECT", req.url, err.message);
    serverSocket.destroy();
  });
});

// ─── Start ────────────────────────────────────────────────────────────────────

server.listen(PORT, "0.0.0.0", function () {
  console.log("Proxy server running on port " + PORT);
  console.log("Auth user: " + PROXY_USER);
  if (allowedEntries.length) {
    console.log("IP allowlist: " + allowedEntries.join(", "));
  } else {
    console.log("IP allowlist: all IPs allowed");
  }
});
