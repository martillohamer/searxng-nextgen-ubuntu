import re, socket, sys
proxy_host = sys.argv[1]
proxy_port = int(sys.argv[2])
def fetch_ip(host, path):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(20)
    try:
        s.connect((proxy_host, proxy_port))
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00": return ""
        hb = host.encode("utf-8")
        req = b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + (80).to_bytes(2, "big")
        s.sendall(req)
        cr = s.recv(10)
        if len(cr) < 2 or cr[0] != 0x05 or cr[1] != 0x00: return ""
        msg = "GET " + path + " HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
        s.sendall(msg.encode("ascii"))
        chunks = []
        while True:
            c = s.recv(4096)
            if not c: break
            chunks.append(c)
        body = b"".join(chunks).decode("utf-8", errors="ignore").split("\r\n\r\n", 1)[-1].strip()
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+", body): return body
        return ""
    except Exception:
        return ""
    finally:
        s.close()
for h, p in [("api.ipify.org", "/"), ("ip-api.com", "/line?fields=query")]:
    ip = fetch_ip(h, p)
    if ip:
        print(ip)
        break
