# TLS and Certificate Troubleshooting

A diagnostic playbook for TLS failures across the Wazuh stack - most notably the indexer's `Received fatal alert: bad_certificate`, but the same flow applies to Filebeat-to-indexer, dashboard-to-indexer, LDAPS, and agent enrollment problems.

## Table of Contents

- [What bad_certificate means](#what-bad_certificate-means)
- [Step-by-step diagnostic flow](#step-by-step-diagnostic-flow)
- [Case study: inverted validity window](#case-study-inverted-validity-window)
- [Hostname/SAN mismatches (LDAPS example)](#hostnamesan-mismatches-ldaps-example)
- [Agent connectivity on 1514/1515](#agent-connectivity-on-15141515)
- [API certificate errors on port 55000](#api-certificate-errors-on-port-55000)
- [Let's Encrypt certificate renewed but not applied](#lets-encrypt-certificate-renewed-but-not-applied)
- [Useful openssl one-liners](#useful-openssl-one-liners)

## What bad_certificate means

When the indexer logs `Received fatal alert: bad_certificate`, Java attempted a TLS handshake and one of the following is true:

- the certificate it loaded is **expired, malformed, or doesn't match the private key**;
- the peer (client or server) did not present a certificate **signed by your CA** - or you pointed Java at the wrong truststore;
- there is a **hostname or time mismatch** (clock skew, or the CN/SAN doesn't match the address being connected to).

## Step-by-step diagnostic flow

### 1. Confirm the system clock

TLS fails if the clock is far off. Check `date` and fix NTP first (`timedatectl`, `chronyd`, `ntpd`) if needed.

### 2. Locate the configured cert/key/truststore

In `/etc/wazuh-indexer/opensearch.yml`:

```yaml
plugins.security.ssl.transport.pemcert_filepath: certs/indexer.pem
plugins.security.ssl.transport.pemkey_filepath: certs/indexer-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: certs/root-ca.pem
```

Confirm the paths point at the files you think they do.

### 3. Inspect the certificate

```bash
openssl x509 -in /etc/wazuh-indexer/certs/indexer.pem -noout \
  -subject -issuer -dates -ext subjectAltName
```

Check:

- `notBefore` / `notAfter` - today must be inside the window;
- the SAN (or CN) includes the hostname/IP that clients actually use to connect.

If either is wrong, regenerate the certificate ([component-certificates.md](component-certificates.md)).

### 4. Verify the key matches the certificate

A mismatched key also produces `bad_certificate`. Both hashes must be identical:

```bash
openssl x509 -noout -modulus -in /etc/wazuh-indexer/certs/indexer.pem | openssl md5
openssl rsa  -noout -modulus -in /etc/wazuh-indexer/certs/indexer-key.pem | openssl md5
```

### 5. Test a live handshake

Connect the same way Java will - transport layer (9300) with mutual TLS, and HTTP layer (9200):

```bash
# Transport layer, presenting the node's cert as a client
openssl s_client -connect 127.0.0.1:9300 \
  -CAfile /etc/wazuh-indexer/certs/root-ca.pem \
  -cert   /etc/wazuh-indexer/certs/indexer.pem \
  -key    /etc/wazuh-indexer/certs/indexer-key.pem

# HTTP layer
openssl s_client -connect <INDEXER_IP>:9200 -CAfile /etc/wazuh-indexer/certs/root-ca.pem

# Authenticated API check with client certs
curl -u admin:<ADMIN_PASSWORD> "https://<INDEXER_IP>:9200/_cat/nodes?v" \
  --cacert /etc/wazuh-indexer/certs/root-ca.pem \
  --cert /etc/wazuh-indexer/certs/indexer.pem \
  --key /etc/wazuh-indexer/certs/indexer-key.pem
```

Any `verify error:` lines (or an immediate handshake failure) are the smoking gun. A successful connection prints the X.509 chain and leaves an open prompt (type `QUIT` to exit).

### 6. Check the truststore (JKS/PKCS#12 setups)

If Java is configured with a keystore instead of PEM files:

```bash
keytool -list -v -keystore /path/to/your.jks -storepass <STORE_PASSWORD>
```

The CA belongs in the **truststore**; the node's cert+key in the **keystore**.

### 7. Regenerate and restart

If anything above failed (expired dates, wrong CN/SAN, missing CA, modulus mismatch), reissue the certificate against the root CA - either with `wazuh-certs-tool.sh` or a manual `openssl x509 -req ... -CA root-ca.pem` (see [component-certificates.md](component-certificates.md#signing-additional-certificates-with-an-existing-root-ca)). Then:

```bash
systemctl restart wazuh-indexer
journalctl -u wazuh-indexer -f
```

The `bad_certificate` errors should stop and cluster nodes should join cleanly.

**TL;DR:** clock → `openssl x509 -dates -ext subjectAltName` → modulus match → `openssl s_client` → CA in truststore → regenerate → restart.

## Case study: inverted validity window

Real-world example of step 3 paying off. The certificate dump showed:

```text
notBefore=May 16 07:34:51 2035 GMT
notAfter =May 14 07:34:51 2035 GMT
```

The certificate is "valid" *from* a date *after* its expiry - it can never be valid, and Java rejects it with `bad_certificate` no matter what else is configured. The fix is simply to reissue with a sane window:

```bash
openssl x509 -req -in indexer.csr \
  -CA root-ca.pem -CAkey root-ca.key -CAcreateserial \
  -out indexer.pem -days 365 -sha256 \
  -extfile <(printf "subjectAltName=IP:<NODE_IP>")
```

Install the new cert/key in `/etc/wazuh-indexer/certs/` (keeping `root-ca.pem` unchanged), restart the indexer, and re-verify both the transport and HTTP ports with `openssl s_client`.

## Hostname/SAN mismatches (LDAPS example)

When the security plugin connects to an external TLS service (e.g. Active Directory over LDAPS on 636) and hostname verification fails:

1. **Use the FQDN that matches the certificate**, not the IP. If the AD certificate is issued for `ldap.example.com`:

    ```yaml
    hosts:
      - ldap.example.com:636
    ```

2. **Inspect the server certificate** to find the actual CN/SAN:

    ```bash
    openssl s_client -connect <LDAP_SERVER>:636 -showcerts
    ```

3. As a temporary test only (never production), hostname verification can be disabled:

    ```yaml
    verify_hostnames: false
    ```

The same rule applies to the Wazuh components themselves: whatever address clients use (IP or FQDN) must appear in the certificate's SAN. See the [LDAP and Active Directory guide](../troubleshooting/ldap-ad.md) for the full setup.

## Agent connectivity on 1514/1515

Agent enrollment (1515) is TLS-protected; agent communication (1514) is not raw TLS. When agents show as disconnected or fail to enroll:

```bash
# From the agent (Linux/macOS): can we reach the manager?
nc -zv <MANAGER_IP> 1514 1515 55000

# From the agent (Windows PowerShell):
(new-object Net.Sockets.TcpClient).Connect("<MANAGER_IP>", 1514)
(new-object Net.Sockets.TcpClient).Connect("<MANAGER_IP>", 1515)

# On the manager: agent status
/var/ossec/bin/agent_control -i <AGENT_ID> | grep Status
```

To probe both ports at protocol level - including timing the TLS handshake on 1515, useful when a proxy or load balancer sits in between - this Python script sends the `#ping` probe on 1514 and performs a TLS echo test on 1515:

<details>
<summary>tls_agent_ping.py</summary>

```python
#!/usr/bin/env python3
import socket
import ssl
import sys
import signal
import time
from struct import pack

DEFAULT_TCP_PORT = 1514
DEFAULT_TLS_PORT = 1515
DEFAULT_TIMEOUT = 10

def sign_handler(signum, frame):
    print(f"[!] Timeout reached {signum}")
    sys.exit(1)

def tcp_ping(addr, port):
    ping_str = b'#ping'
    pong_str = b'#pong'
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(DEFAULT_TIMEOUT)
        sock.connect((addr, port))
        buffer = pack('<I', len(ping_str)) + ping_str
        sock.send(buffer)
        response = sock.recv(64)
        sock.close()
        if response[4:] != pong_str:
            print(f"[x] Invalid response: {response[4:]}")
            return False
        print("[ok] Valid response")
        return True
    except Exception as e:
        print(f"[!] TCP ping error: {e}")
        return False

def tls_ping(addr, port):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    message = "Echo\n"
    try:
        t0 = time.time()
        raw_sock = socket.create_connection((addr, port), timeout=DEFAULT_TIMEOUT)
        t1 = time.time()
        ssl_sock = context.wrap_socket(raw_sock, server_hostname=addr)
        t2 = time.time()
        ssl_sock.sendall(message.encode())
        response = ssl_sock.recv(4096)
        t3 = time.time()
        ssl_sock.shutdown(socket.SHUT_RDWR)
        ssl_sock.close()
        print(f"[+] TCP connection time: {t1 - t0:.4f}s")
        print(f"[+] TLS handshake time: {t2 - t1:.4f}s")
        print(f"[+] Message+Response time: {t3 - t2:.4f}s")
        print(f"[+] Total time: {t3 - t0:.4f}s")
        if response.startswith(b'ERROR: Invalid request for new agent'):
            print("[!] Server response: OK")
            return True
        print(f"[+] Server response:\n{response.decode(errors='ignore')}")
        return True
    except Exception as e:
        print(f"[!] TLS ping error: {e}")
        return False

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <address>[:<port>]")
        sys.exit(1)
    address_input = sys.argv[1]
    if ':' in address_input:
        host, port = address_input.split(':', 1)
        port = int(port)
    else:
        host = address_input
        port = DEFAULT_TCP_PORT
    signal.signal(signal.SIGALRM, sign_handler)
    signal.alarm(DEFAULT_TIMEOUT)
    print(f"[+] Connecting to {host}:{port}")
    if port == DEFAULT_TCP_PORT:
        print("[+] Mode detected: TCP Ping (#ping/#pong)")
        success = tcp_ping(host, port)
    elif port == DEFAULT_TLS_PORT:
        print("[+] Mode detected: TLS Echo Test")
        success = tls_ping(host, port)
    else:
        print(f"[!] Unknown port {port} (only 1514=TCP or 1515=TLS supported)")
        sys.exit(1)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
```

</details>

Run it against both a direct manager address and (if applicable) the proxy/load-balancer address and compare - a handshake that works direct but fails through the proxy points at the proxy configuration. See also the official [agent enrollment troubleshooting guide](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/troubleshooting.html).

If agents repeatedly try to **re-register** instead of reconnecting (rejected because a valid key already exists), tune the agent's `ossec.conf`:

```xml
<force_reconnect_interval>1h</force_reconnect_interval>
<time-reconnect>300</time-reconnect>
```

If **new** agents cannot enroll on 1515 while already-registered agents keep reporting normally, suspect the manager's dedicated enrollment certificate `/var/ossec/etc/sslmanager.cert` rather than the shared bundle - most often it has expired. It is only used during registration, so its expiry does not disconnect existing agents. Check and renew it as described in [component-certificates.md](component-certificates.md#the-manager-enrollment-certificate-sslmanagercert):

```bash
openssl x509 -enddate -noout -in /var/ossec/etc/sslmanager.cert
```

## API certificate errors on port 55000

The Wazuh server REST API (TCP 55000) has its own certificate, separate from the indexer/Filebeat/dashboard bundle. A recurring failure mode after replacing it is that clients (agents doing remote upgrades, the dashboard, custom scripts) report:

```text
tls: failed to verify certificate: x509: certificate signed by unknown authority
```

while a plain `openssl s_client` against the certificate file looks valid. This is almost always an **incomplete chain**: the certificate is signed by an intermediate CA, and the API serves only the leaf certificate, so a client that does not already hold the intermediate cannot build a path to the root.

Confirm it by looking at what the API actually sends on the wire:

```bash
openssl s_client -connect <MANAGER_IP>:55000 -showcerts
```

The tell-tale is a `verify error:num=20:unable to get local issuer certificate` with only the leaf (and no intermediate) in the `Certificate chain` block. The fix has two halves - serve the full chain from the manager and trust the CA on the client - both detailed in [component-certificates.md](component-certificates.md#the-wazuh-server-api-certificate-port-55000). In short:

```bash
# On the manager: build leaf + intermediate and point api.yaml at it
cat server.crt intermediate.crt > /var/ossec/api/configuration/ssl/server-chain.crt
# (set `cert: "server-chain.crt"` in /var/ossec/api/configuration/api.yaml, then restart)

# On each client host: trust the intermediate + root CA
cp root-wazuh-api.crt /usr/local/share/ca-certificates/
update-ca-certificates
```

A successful chain lets you authenticate without `-k`:

```bash
TOKEN=$(curl -u <API_USER>:<API_PASSWORD> \
  -X POST "https://<MANAGER_IP>:55000/security/user/authenticate?raw=true")
curl -X GET "https://<MANAGER_IP>:55000/?pretty=true" -H "Authorization: Bearer $TOKEN"
```

## Let's Encrypt certificate renewed but not applied

A dashboard that was secure at install time starts being reported as "not secure" roughly 90 days later, and the dashboard log shows a TLS alert such as `sslv3 alert certificate unknown`. `certbot renew` reports success, yet the browser still sees the expired certificate.

The usual root cause is that the deployment **copied** `fullchain.pem` / `privkey.pem` from `/etc/letsencrypt/live/<domain>/` into the component's certs directory (e.g. `/etc/wazuh-dashboard/certs/`) instead of pointing the service straight at the live files. Certbot renews the files under `/etc/letsencrypt/live/`, but the stale copies the dashboard actually serves are never refreshed. Compare the timestamps to confirm:

```bash
ls -l /etc/letsencrypt/live/<domain>/fullchain.pem
ls -l /etc/wazuh-dashboard/certs/fullchain.pem   # older -> this is the problem
```

Two ways to fix it:

- **Point the service directly at the live files** (`server.ssl.certificate` / `server.ssl.key`, or the NGINX `ssl_certificate*` directives) so no copy step exists.
- **Automate the copy on renewal.** Add a certbot `--deploy-hook` (runs only when a certificate actually changes) or a small scheduled job that copies the renewed files into the certs directory and restarts the service. A minimal timestamp-driven script:

    ```bash
    #!/bin/bash
    SRC=/etc/letsencrypt/live/<domain>
    DEST=/etc/wazuh-dashboard/certs
    changed=0
    for f in privkey.pem fullchain.pem; do
      if [ "$SRC/$f" -nt "$DEST/$f" ]; then
        cp "$SRC/$f" "$DEST/$f"; changed=1
      fi
    done
    [ "$changed" -eq 1 ] && systemctl restart wazuh-dashboard
    ```

    Schedule it (for example monthly) with `crontab -e`:

    ```cron
    0 0 1 * * /path/to/checkcerts.sh
    ```

Remember to keep file ownership/permissions correct on the copied files (`chown wazuh-dashboard:wazuh-dashboard`, mode `400`).

## Useful openssl one-liners

```bash
# Dump the full chain of a remote HTTPS endpoint
openssl s_client -host wazuh.example.com -port 443 -showcerts

# Pretty-print every certificate in a remote chain
openssl s_client -showcerts -connect wazuh.example.com:443 \
  | openssl crl2pkcs7 -nocrl -certfile /dev/stdin \
  | openssl pkcs7 -noout -print_certs -text | less

# Quick subject + SAN check of a remote endpoint
echo | openssl s_client -connect wazuh.example.com:443 \
  | openssl x509 -noout -text | grep -E 'Subject:|DNS:' -A2

# Verify an API endpoint against a specific root CA
curl -v --cacert /path/to/root-ca.pem https://wazuh.example.com/api/endpoint

# Local file: subject, issuer, validity, SANs
openssl x509 -in node.pem -noout -subject -issuer -dates -ext subjectAltName

# Does this key belong to this cert?
openssl x509 -noout -modulus -in node.pem | openssl md5
openssl rsa  -noout -modulus -in node-key.pem | openssl md5
```
