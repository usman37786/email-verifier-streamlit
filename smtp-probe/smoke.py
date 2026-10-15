"""Live smoke test: fake SMTP + real probe HTTP server + real pipeline.

Not part of the unit suite (it is a manual end-to-end check). Run from
project/ with:  python smtp-probe/smoke.py
"""
import importlib.util
import json
import os
import socket
import sys
import threading
from http.server import ThreadingHTTPServer

# Run from anywhere; the verifier core lives one directory up.
PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT)
os.chdir(PROJECT)

# --- minimal SMTP server: accepts real users, rejects random probes --------


def smtp_thread(reply_for, log):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def handle(conn):
        conn.settimeout(5)
        try:
            lines = conn.makefile("rb")
            conn.sendall(b"220 smoke ESMTP\r\n")
            while True:
                raw = lines.readline()
                if not raw:
                    break
                cmd = raw.decode("utf-8", "ignore").strip()
                verb = cmd.split(" ", 1)[0].upper()
                if verb == "EHLO":
                    conn.sendall(b"250-smoke\r\n250 OK\r\n")
                elif verb == "MAIL":
                    conn.sendall(b"250 OK\r\n")
                elif verb == "RCPT":
                    local = cmd.split("<", 1)[-1].rstrip(">").split("@")[0]
                    code, text = reply_for(local)
                    conn.sendall(("%d %s\r\n" % (code, text)).encode())
                elif verb == "RSET":
                    conn.sendall(b"250 OK\r\n")
                elif verb == "QUIT":
                    conn.sendall(b"221 Bye\r\n")
                    break
                else:
                    conn.sendall(b"502 Not implemented\r\n")
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def accept():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    t = threading.Thread(target=accept, daemon=True)
    t.start()
    return port, stop, srv


# --- load the probe module ------------------------------------------------

spec = importlib.util.spec_from_file_location("probe_mod", "smtp-probe/probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
probe.ALLOW_INSECURE = True          # loopback is otherwise "unsafe"
probe._port25_open = lambda: True    # skip the 3 s external TCP test


def run_case(title, reply_for, domain):
    port, stop, srv = smtp_thread(reply_for, None)
    # Aim the probe at this fake server.
    probe.resolve_mx = lambda d, timeout_s=None: (["mx.example.test"], None)
    probe._resolve_ips = lambda host: ["93.184.216.34"]

    def fake_init(self, h, timeout_s):
        import smtplib

        self.host = h
        client = smtplib.SMTP(timeout=timeout_s)
        client.connect("127.0.0.1", port)
        client.ehlo_or_helo_if_needed()
        self.client = client

    probe.ProbeSession.__init__ = fake_init  # type: ignore

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), probe.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    probe_url = "http://127.0.0.1:%d" % httpd.server_port

    from core.pipeline import verify

    def doh(name, rtype, timeout_ms):
        if rtype == "MX":
            return {"Status": 0, "Answer": [{"name": name, "type": 15,
                                             "data": "10 mx.example.test."}]}
        if rtype == "A":
            return {"Status": 0, "Answer": [{"name": "mx.example.test",
                                             "type": 1, "data": "93.184.216.34"}]}
        return {"Status": 0, "Answer": []}

    d = verify("alice@" + domain, {
        "doh_query": doh, "smtp": True, "use_cache": False,
        "probe_url": probe_url, "deadline_ms": 15000,
    }).to_dict()
    httpd.shutdown()
    stop.set()
    srv.close()

    print("%-42s -> %-14s %s" % (title, d["status"], d["reason_code"]))
    print("%-42s    level=%-5s flags=%s" % ("", d["level"], d["flags"]))
    print("%-42s    message=%s" % ("", d["reason"]))
    print()
    return d


def main():
    print("smtp-probe end-to-end smoke test\n" + "=" * 60)
    # Distinct domain per case: the probe caches catch-all verdicts per domain
    # for 24 h, so reusing one domain across different fake servers would be
    # answered from cache.
    probe.Handler.log_message = lambda *a, **k: None

    d1 = run_case("real mailbox, random rejected",
                  lambda local: (550, "5.1.1 User unknown")
                  if local.startswith("zq7") else (250, "OK"),
                  "realmail.example")
    assert d1["status"] == "deliverable", d1

    d2 = run_case("catch-all domain (accepts everything)",
                  lambda local: (250, "OK"), "catchall.example")
    assert d2["status"] == "risky", d2

    d3 = run_case("non-existent mailbox",
                  lambda local: (550, "5.1.1 User unknown"),
                  "bogus.example")
    assert d3["status"] == "undeliverable", d3

    d4 = run_case("greylisted (4xx)",
                  lambda local: (451, "4.7.1 retry later"), "grey.example")
    assert d4["status"] == "unknown", d4

    print("=" * 60)
    print("ALL FOUR VERDICTS CORRECT -- the probe produces real S6 results.")


if __name__ == "__main__":
    main()
