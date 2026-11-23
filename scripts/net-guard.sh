#!/usr/bin/env bash
# Run as root before any target is installed (the workflow uses sudo). Deny by default, and log
# what is denied so it reaches the run telemetry (src/sandbox-net.mjs reads the kernel log back):
#   - ISK-SBX (forwarded traffic, jumped to from DOCKER-USER, which is checked before Docker's own
#     rules): the sandbox networks live in 10.213.52.0/22 (src/sandbox-net.mjs NETS). Traffic that
#     stays inside one of them (10.213.53.0/24 for running, 10.213.54.0/24 for installing) passes;
#     anything else from or to the range is logged ("isk-sbx-fwd: ") and dropped. They are
#     --internal networks, so this is a second wall, and the log is the evidence;
#   - DOCKER-USER also drops 169.254.0.0/16 (instance metadata, link-local) and 168.63.129.16 (the
#     Azure host agent / wire server) for every container network, the proxy's egress network too;
#   - ISK-SBX-IN (traffic from a container to an address of the host): everything arriving on
#     docker0 or a br-* bridge is logged ("isk-sbx-in: ") and dropped, so nothing on the runner
#     (its own services, the Docker API if it ever listened on TCP) is reachable from a container;
#   - ISK-SBX6: the same for IPv6, forwarded or to the host ("isk-sbx-fwd6: ", "isk-sbx-in6: ").
#     The sandbox networks have no IPv6; this catches link-local and anything else that tries.
# It also writes the resolv.conf files the sandbox containers get (read-only): the network logger
# is the only name server (src/sandbox-net.mjs resolvConf). Logging is rate limited.
# Idempotent. Prints nothing about targets.
set -euo pipefail
command -v iptables >/dev/null || { echo "harness error: iptables not found"; exit 1; }
command -v ip6tables >/dev/null || { echo "harness error: ip6tables not found"; exit 1; }
range=10.213.52.0/22
run_net=10.213.53.0/24
install_net=10.213.54.0/24
etc_dir="${SANDBOX_ETC_DIR:-/etc/isokron-sandbox}"
limit=(-m limit --limit 20/second --limit-burst 200)

iptables -N DOCKER-USER 2>/dev/null || true
# The DOCKER-USER rules hold only if forwarded traffic passes through that chain (Docker's iptables
# integration adds the jump). Without it they would sit unused, so stop instead of printing "guarded"
# (R2-9). No ACCEPT may come before the jump either.
iptables -C FORWARD -j DOCKER-USER 2>/dev/null || { echo "harness error: DOCKER-USER is not in FORWARD"; exit 1; }
iptables -S FORWARD | awk '$1 == "-A" && / -j DOCKER-USER$/ { exit 0 } $1 == "-A" && / -j ACCEPT/ { exit 1 }' \
  || { echo "harness error: FORWARD accepts traffic before DOCKER-USER"; exit 1; }

# A chain is rebuilt from scratch each time, so a second run leaves the same rules.
fresh() { "$1" -N "$2" 2>/dev/null || "$1" -F "$2"; }

fresh iptables ISK-SBX
iptables -A ISK-SBX -s "$run_net" -d "$run_net" -j RETURN
iptables -A ISK-SBX -s "$install_net" -d "$install_net" -j RETURN
iptables -A ISK-SBX "${limit[@]}" -j LOG --log-prefix 'isk-sbx-fwd: ' --log-level 4
iptables -A ISK-SBX -j DROP
for dir in -s -d; do
  iptables -C DOCKER-USER "$dir" "$range" -j ISK-SBX 2>/dev/null || iptables -I DOCKER-USER "$dir" "$range" -j ISK-SBX
done
for dst in 169.254.0.0/16 168.63.129.16/32; do
  iptables -C DOCKER-USER -d "$dst" -j DROP 2>/dev/null || iptables -I DOCKER-USER -d "$dst" -j DROP
done

fresh iptables ISK-SBX-IN
iptables -A ISK-SBX-IN "${limit[@]}" -j LOG --log-prefix 'isk-sbx-in: ' --log-level 4
iptables -A ISK-SBX-IN -j DROP
for ifc in docker0 'br-+'; do
  # An older version of this script dropped without logging; the jump replaces that rule.
  while iptables -D INPUT -i "$ifc" -j DROP 2>/dev/null; do :; done
  iptables -C INPUT -i "$ifc" -j ISK-SBX-IN 2>/dev/null || iptables -I INPUT -i "$ifc" -j ISK-SBX-IN
done

fresh ip6tables ISK-SBX6
ip6tables -A ISK-SBX6 "${limit[@]}" -j LOG --log-prefix 'isk-sbx-fwd6: ' --log-level 4
ip6tables -A ISK-SBX6 -j DROP
fresh ip6tables ISK-SBX6-IN
ip6tables -A ISK-SBX6-IN "${limit[@]}" -j LOG --log-prefix 'isk-sbx-in6: ' --log-level 4
ip6tables -A ISK-SBX6-IN -j DROP
for ifc in docker0 'br-+'; do
  for dir in -i -o; do
    ip6tables -C FORWARD "$dir" "$ifc" -j ISK-SBX6 2>/dev/null || ip6tables -I FORWARD "$dir" "$ifc" -j ISK-SBX6
  done
  ip6tables -C INPUT -i "$ifc" -j ISK-SBX6-IN 2>/dev/null || ip6tables -I INPUT -i "$ifc" -j ISK-SBX6-IN
done

# Every name a sandbox container looks up goes to the network logger at .2 of its network.
install -d -m 0755 "$etc_dir"
for pair in run:10.213.53.2 install:10.213.54.2; do
  net="${pair%%:*}"
  tmp="$(mktemp "$etc_dir/.resolv.XXXXXX")"
  printf '# isokron sandbox: every name resolves to the network logger, which logs it\nnameserver %s\noptions ndots:0 timeout:1 attempts:1\n' "${pair#*:}" >"$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$etc_dir/resolv-$net.conf"
done
echo "container networks guarded"
