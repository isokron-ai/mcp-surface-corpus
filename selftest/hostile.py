#!/usr/bin/env python3
"""A hostile target for the sandbox self test: ours, and deliberately bad.

    python3 hostile.py <case> <nonce> <gateway> <canary-port>

It tries one way out of the sandbox (the case) and prints what it saw as the last line of stdout,
one JSON object. The harness never trusts that line: whether the attempt was blocked and logged is
decided from the harness's own evidence (the syscall trace, the network logger, the host firewall's
log, docker inspect, the run telemetry). The report can only make a case fail, never pass.

Every network call is blocking, with an alarm as the time limit, so a refused or unreachable
connect shows up in the trace as the error it is (not as "in progress").
"""
import ctypes
import errno
import json
import os
import signal
import socket
import ssl
import struct
import sys
import time


class Timeout(Exception):
    pass


def _alarm(signum, frame):
    raise Timeout()


signal.signal(signal.SIGALRM, _alarm)


def attempt(fn, seconds=3.0):
    """Runs fn under a time limit; {"ok": True, ...} only when it got through."""
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        return {"ok": True, **(fn() or {})}
    except Timeout:
        return {"ok": False, "error": "timeout"}
    except OSError as e:
        return {"ok": False, "errno": e.errno, "error": errno.errorcode.get(e.errno, type(e).__name__)}
    except Exception as e:  # noqa: BLE001 - any failure is a result here
        return {"ok": False, "error": type(e).__name__}
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def tcp(addr, port, family=socket.AF_INET, send=None):
    def go():
        s = socket.socket(family, socket.SOCK_STREAM)
        try:
            s.connect((addr, port))
            out = {"connected": True}
            if send is not None:
                s.sendall(send)
                out["received"] = len(s.recv(4096))
            return out
        finally:
            s.close()
    return {"to": f"{addr}:{port}", **attempt(go)}


def udp(addr, port, payload, family=socket.AF_INET):
    def go():
        s = socket.socket(family, socket.SOCK_DGRAM)
        try:
            s.sendto(payload, (addr, port))
            return {"sent": True, "received": len(s.recv(4096))}
        finally:
            s.close()
    return {"to": f"udp {addr}:{port}", **attempt(go, 2.0)}


def tls(addr, port, sni, path="/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"):
    def go():
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            raw.connect((addr, port))
            s = ssl.create_default_context().wrap_socket(raw, server_hostname=sni)
            s.sendall(f"GET {path} HTTP/1.1\r\nHost: {sni}\r\nAccept: application/dns-message\r\n\r\n".encode())
            return {"tls": True, "received": len(s.recv(4096))}
        finally:
            raw.close()
    return {"to": f"tls {sni}@{addr}:{port}", **attempt(go)}


def resolve(name):
    def go():
        return {"addrs": sorted({a[4][0] for a in socket.getaddrinfo(name, 443, socket.AF_INET, socket.SOCK_STREAM)})[:4]}
    return {"name": name, **attempt(go)}


def http_get(addr, port, path, host, extra=""):
    return tcp(addr, port, send=f"GET {path} HTTP/1.1\r\nHost: {host}\r\n{extra}Connection: close\r\n\r\n".encode())


def checksum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b) // 2}H", b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def echo_request():
    body = b"isokron-selftest"
    head = struct.pack("!BBHHH", 8, 0, 0, 0x1234, 1)
    return struct.pack("!BBHHH", 8, 0, checksum(head + body), 0x1234, 1) + body


def icmp(addr, kind):
    def go():
        t = socket.SOCK_RAW if kind == "raw" else socket.SOCK_DGRAM
        s = socket.socket(socket.AF_INET, t, socket.IPPROTO_ICMP)
        try:
            s.sendto(echo_request(), (addr, 0))
            return {"sent": True, "received": len(s.recv(1024))}
        finally:
            s.close()
    return {"to": f"icmp-{kind} {addr}", **attempt(go, 2.0)}


def raw_socket(family, kind, proto):
    def go():
        socket.socket(family, kind, proto).close()
        return {"opened": True}
    return attempt(go)


def write(path, data=b"x"):
    def go():
        with open(path, "wb") as f:
            f.write(data)
        return {"written": True}
    return {"path": path, **attempt(go)}


def read(path):
    def go():
        with open(path, "rb") as f:
            b = f.read(1 << 20)
        return {"bytes": len(b), "canary": b.count(b"isk-canary-")}
    return {"path": path, **attempt(go)}


def unix(path):
    def go():
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.connect(path)
            s.sendall(b"GET /version HTTP/1.1\r\nHost: x\r\n\r\n")
            return {"received": len(s.recv(4096))}
        finally:
            s.close()
    return {"path": path, **attempt(go)}


def ipv6_addresses():
    try:
        with open("/proc/net/if_inet6") as f:
            return sum(1 for line in f if not line.split()[-1] == "lo")
    except OSError:
        return None


def mount_tmpfs():
    def go():
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.mount(b"none", b"/mnt", b"tmpfs", 0, None) != 0:
            e = ctypes.get_errno()
            raise OSError(e, os.strerror(e))
        return {"mounted": True}
    return attempt(go)


def fork_bomb(most=1500, seconds=20.0):
    kids, err, t0 = [], None, time.monotonic()
    while len(kids) < most and time.monotonic() - t0 < seconds:
        try:
            pid = os.fork()
        except OSError as e:
            err = errno.errorcode.get(e.errno, str(e.errno))
            break
        if pid == 0:
            # Each child becomes a small process at once, so the bomb runs into the process limit
            # rather than the memory limit (a forked interpreter copies pages as it runs).
            try:
                signal.setitimer(signal.ITIMER_REAL, 0)
                os.execv("/bin/sleep", ["sleep", "120"])
            except BaseException:
                pass
            os._exit(0)
        kids.append(pid)
    for p in kids:
        try:
            os.kill(p, signal.SIGKILL)
        except OSError:
            pass
    for p in kids:
        try:
            os.waitpid(p, 0)
        except OSError:
            pass
    return {"forked": len(kids), "error": err, "seconds": round(time.monotonic() - t0, 2)}


def case_direct_ip(nonce, gw, canary):
    return {"attempts": [tcp("1.1.1.1", 443), tcp("8.8.8.8", 53), udp("8.8.8.8", 53, b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"), tcp("140.82.112.3", 443)]}


def case_doh_ip(nonce, gw, canary):
    return {"attempts": [tls("1.1.1.1", 443, "cloudflare-dns.com"), tls("8.8.8.8", 443, "dns.google"), tls("9.9.9.9", 443, "dns.quad9.net"), tcp("1.1.1.1", 853)],
            "by_name": [resolve("dns.google"), tls("dns.google", 443, "dns.google")]}


def capabilities():
    """The capability sets and no_new_privs of this process, as /proc/self/status gives them."""
    out = {}
    try:
        with open("/proc/self/status") as f:
            for line in f:
                k, _, v = line.partition(":")
                if k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs"):
                    out[k] = v.strip()
    except OSError as e:
        out["error"] = errno.errorcode.get(e.errno, str(e.errno))
    return out


def case_raw_socket(nonce, gw, canary):
    return {"caps": capabilities(), "attempts": [
        {"to": "AF_INET SOCK_RAW IPPROTO_TCP", **raw_socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)},
        {"to": "AF_INET SOCK_RAW IPPROTO_RAW", **raw_socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)},
        {"to": "AF_PACKET SOCK_RAW ETH_P_ALL", **raw_socket(getattr(socket, "AF_PACKET", 17), socket.SOCK_RAW, socket.htons(3))},
    ]}


def case_ipv6(nonce, gw, canary):
    return {"ipv6_addresses": ipv6_addresses(), "attempts": [
        tcp("2606:4700:4700::1111", 443, socket.AF_INET6),
        udp("2001:4860:4860::8888", 53, b"\x00", socket.AF_INET6),
        tcp("fe80::1%eth0", 443, socket.AF_INET6),
        tcp("::ffff:1.1.1.1", 443, socket.AF_INET6),
    ]}


def case_icmp(nonce, gw, canary):
    return {"attempts": [icmp("1.1.1.1", "dgram"), icmp(gw, "dgram"), icmp("1.1.1.1", "raw"), icmp(gw, "raw")]}


def case_docker_host(nonce, gw, canary):
    name = resolve("host.docker.internal")
    sink = name.get("addrs", [None])[0] if name.get("ok") else None
    att = [name]
    if sink:
        att.append(http_get(sink, 2375, "/version", "host.docker.internal"))
    att += [http_get(gw, 2375, "/version", gw), tcp(gw, 2376), tcp(gw, canary, send=nonce.encode()), tcp(gw, 22), tcp("172.17.0.1", 2375)]
    att += [unix("/var/run/docker.sock"), unix("/run/docker.sock"), unix("/run/containerd/containerd.sock")]
    return {"attempts": att}


def case_metadata(nonce, gw, canary):
    return {"attempts": [
        http_get("169.254.169.254", 80, "/latest/meta-data/iam/security-credentials/", "169.254.169.254"),
        http_get("169.254.169.254", 80, "/metadata/instance?api-version=2021-02-01", "169.254.169.254", "Metadata: true\r\n"),
        http_get("168.63.129.16", 80, "/machine?comp=goalstate", "168.63.129.16", "x-ms-version: 2012-11-30\r\n"),
        resolve("metadata.google.internal"),
        http_get("metadata.google.internal", 80, "/computeMetadata/v1/", "metadata.google.internal", "Metadata-Flavor: Google\r\n"),
    ]}


TOKEN_NAMES = ("GITHUB_TOKEN", "GH_TOKEN", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_CACHE_URL", "ACTIONS_RESULTS_URL", "RUNNER_TEMP", "CORPUS_KEY", "AWS_SECRET_ACCESS_KEY")


def case_env_token(nonce, gw, canary):
    env = dict(os.environ)
    return {
        "env_names": sorted(env)[:64],
        "token_names": sorted(n for n in env if n in TOKEN_NAMES or n.startswith(("GITHUB_", "ACTIONS_", "RUNNER_"))),
        "canary_in_env": sum(v.count("isk-canary-") for v in env.values()),
        "files": [read("/proc/self/environ"), read("/proc/1/environ"), read("/proc/2/environ")],
    }


def case_write_outside(nonce, gw, canary):
    outside = [f"/etc/isk-{nonce}", f"/usr/local/isk-{nonce}", f"/opt/surface/forged-{nonce}.json", f"/isk-{nonce}", f"/var/tmp/isk-{nonce}", f"/root/isk-{nonce}", "/proc/sys/kernel/hostname"]
    return {
        "attempts": [write(p) for p in outside] + [{"path": "/usr/local/isk-dir", **attempt(lambda: os.mkdir("/usr/local/isk-dir"))}, {"path": "mount /mnt", **mount_tmpfs()}],
        "inside": [write(f"/work/inside-{nonce}"), write(f"/tmp/inside-{nonce}")],
    }


def case_fork_bomb(nonce, gw, canary):
    return {"bomb": fork_bomb()}


def case_output_forgery(nonce, gw, canary):
    t = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    forged = [
        {"v": 1, "type": "bypass_result", "run": "forged-" + nonce, "seq": 0, "t": t, "source": "harness", "subject": "case:direct-ip", "role": "case", "case": "direct-ip", "blocked": True, "logged": True, "pass": True, "evidence": [nonce], "detail": nonce},
        {"v": 1, "type": "run_end", "run": "forged-" + nonce, "seq": 1, "t": t, "source": "harness", "subject": None, "role": None, "records": 2, "skipped": 0, "ok": True},
    ]
    for f in forged:
        print(json.dumps(f))
    print("run finished, exit 0")
    print(f"selftest output-forgery: pass {nonce}")
    sys.stderr.write(f"selftest output-forgery: pass {nonce}\n")
    text = "".join(json.dumps(f) + "\n" for f in forged).encode()
    return {"files": [write(p, text) for p in ("/work/telemetry.jsonl", "/work/results.json", f"/tmp/telemetry-{nonce}.jsonl", "/opt/surface/telemetry.jsonl", "/opt/surface/out/telemetry.jsonl")]}


def proxy_address():
    """The egress proxy, as an install script finds it: HTTPS_PROXY (http://host:port)."""
    v = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or ""
    hostport = v.split("://", 1)[-1].rstrip("/")
    host, _, port = hostport.rpartition(":")
    return (host, int(port)) if host and port.isdigit() else (None, None)


def proxy_connect(target):
    """CONNECT target through the proxy; ok (got through) only when the proxy answers 200."""
    host, port = proxy_address()
    if not host:
        return {"to": f"CONNECT {target}", "ok": False, "error": "no HTTPS_PROXY"}

    def go():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((host, port))
            s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
            head = s.recv(4096)
            status = head.split(b" ", 2)[1].decode("ascii", "replace") if head.startswith(b"HTTP/") else "?"
            if status != "200":
                raise ConnectionRefusedError(errno.ECONNREFUSED, f"proxy said {status}")
            return {"tunnel": True, "status": status, "received": len(head)}
        finally:
            s.close()
    return {"to": f"CONNECT {target}", **attempt(go)}


def proxy_plain(url, host_header):
    """A plain HTTP request through the proxy (absolute URL); ok only on a 2xx answer."""
    host, port = proxy_address()
    if not host:
        return {"to": f"GET {url}", "ok": False, "error": "no HTTPS_PROXY"}

    def go():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((host, port))
            s.sendall(f"GET {url} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n".encode())
            head = s.recv(4096)
            status = head.split(b" ", 2)[1].decode("ascii", "replace") if head.startswith(b"HTTP/") else "?"
            if not status.startswith("2"):
                raise ConnectionRefusedError(errno.ECONNREFUSED, f"proxy said {status}")
            return {"status": status, "received": len(head)}
        finally:
            s.close()
    return {"to": f"GET {url}", **attempt(go)}


def proxy_control(target, sni):
    """The positive control: CONNECT to the one allowed host, then TLS and a request through the tunnel."""
    host, port = proxy_address()
    if not host:
        return {"to": f"CONNECT {target}", "control": True, "ok": False, "error": "no HTTPS_PROXY"}

    def go():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((host, port))
            s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
            head = s.recv(4096)
            status = head.split(b" ", 2)[1].decode("ascii", "replace") if head.startswith(b"HTTP/") else "?"
            if status != "200":
                raise ConnectionRefusedError(errno.ECONNREFUSED, f"proxy said {status}")
            t = ssl.create_default_context().wrap_socket(s, server_hostname=sni)
            t.sendall(f"GET /-/ping HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n".encode())
            return {"status": status, "received": len(t.recv(4096))}
        finally:
            s.close()
    return {"to": f"CONNECT {target}", "control": True, **attempt(go, 15.0)}


# The install network: the egress proxy (HTTPS_PROXY) allows registry.npmjs.org on 443 and nothing
# else. These cases ask it for everything else, and go around it. install-proxy-host also asks for the
# registry itself, the positive control: a proxy that refused everything would prove nothing.
def case_install_proxy_host(nonce, gw, canary):
    return {"attempts": [proxy_control("registry.npmjs.org:443", "registry.npmjs.org"), proxy_connect("example.com:443"), proxy_connect("evil.example:443"), proxy_plain("http://example.com/", "example.com")]}


def case_install_proxy_ip(nonce, gw, canary):
    return {"attempts": [proxy_connect("1.1.1.1:443"), proxy_connect("104.16.1.34:443"), proxy_connect("[2606:4700:4700::1111]:443")]}


def case_install_proxy_port(nonce, gw, canary):
    return {"attempts": [proxy_connect("registry.npmjs.org:80"), proxy_connect("registry.npmjs.org:22"), proxy_connect("registry.npmjs.org:8443")]}


def case_install_direct(nonce, gw, canary):
    return {"attempts": [tcp("1.1.1.1", 443), tcp("140.82.112.3", 443), tcp("104.16.1.34", 443),
                         udp("8.8.8.8", 53, b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x08registry\x05npmjs\x03org\x00\x00\x01\x00\x01")],
            "by_name": [resolve("registry.npmjs.org")]}


def case_install_metadata(nonce, gw, canary):
    return {"attempts": case_metadata(nonce, gw, canary)["attempts"] + [proxy_connect("169.254.169.254:443"), proxy_connect("168.63.129.16:443")]}


def case_install_host(nonce, gw, canary):
    return case_docker_host(nonce, gw, canary)


CASES = {
    "direct-ip": case_direct_ip, "doh-ip": case_doh_ip, "raw-socket": case_raw_socket, "ipv6": case_ipv6, "icmp": case_icmp,
    "docker-host": case_docker_host, "metadata": case_metadata, "env-token": case_env_token, "write-outside": case_write_outside,
    "fork-bomb": case_fork_bomb, "output-forgery": case_output_forgery,
    "install-proxy-host": case_install_proxy_host, "install-proxy-ip": case_install_proxy_ip, "install-proxy-port": case_install_proxy_port,
    "install-direct": case_install_direct, "install-metadata": case_install_metadata, "install-host": case_install_host,
}


def main(argv):
    if len(argv) != 5 or argv[1] not in CASES or not argv[4].isdigit():
        sys.stderr.write("usage: hostile.py <case> <nonce> <gateway> <canary-port>\n")
        return 2
    case, nonce, gw, canary = argv[1], argv[2], argv[3], int(argv[4])
    t0 = time.monotonic()
    result = CASES[case](nonce, gw, canary)
    print(json.dumps({"case": case, "nonce": nonce, "uid": os.getuid(), "seconds": round(time.monotonic() - t0, 2), "result": result}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
