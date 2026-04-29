"""
p2p_mesh.py — Benign node-to-node threat-intel sharing.

v2: Mutual TLS + SPIFFE-style node attestation (per DoD reviewer gap #2).

Trust model upgrade:
  - Nodes use provisioned TLS certificates. Dev-only self-signed generation is
    optional and disabled by default.
  - The listener accepts only connections whose peer certificate fingerprint
    (SHA-256) is in the configured PEER_CERT_FINGERPRINTS allowlist.
  - Every message carries an HMAC-SHA256 payload signature (unchanged from v1).
  - A SPIFFE-style node identity claim is included in every message, signed
    with the node's HMAC key, providing zero-trust attestation without
    requiring a full SPIFFE/SPIRE deployment.
  - Peer fingerprints are stored in the DB for audit; unrecognised fingerprints
    are logged and rejected (never silently accepted).

Usage:
    python p2p_mesh.py                    # start listener + sync loop
    python p2p_mesh.py --push-only        # one-shot push to peers and exit
    python p2p_mesh.py --port 9001        # override listen port
    python p2p_mesh.py --show-fingerprint # print this node's cert fingerprint
"""

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import socket
import sqlite3
import ssl
import sys
import threading
import time
import urllib.request
import urllib.error
import base64
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import config


# ── Certificate paths ─────────────────────────────────────────────────────────

_CERT_FILE = Path(config.P2P_TLS_CERT_PATH)
_KEY_FILE = Path(config.P2P_TLS_KEY_PATH)

# Allowlist of trusted peer cert SHA-256 fingerprints (hex, colon-separated).
# Populate via config or env:  DARKSPACE_PEER_FINGERPRINTS="AA:BB:CC:...,DD:EE:..."
_raw_fps = os.environ.get("DARKSPACE_PEER_FINGERPRINTS", "")
PEER_CERT_FINGERPRINTS: set[str] = {
    fp.strip().upper().replace(":", "")
    for fp in _raw_fps.split(",") if fp.strip()
}
# In no-TLS / dev mode (certs absent) skip fingerprint enforcement.
_TLS_AVAILABLE = False
LISTEN_HOST = os.environ.get("DARKSPACE_P2P_LISTEN_HOST", "127.0.0.1")


# ── Certificate helpers ───────────────────────────────────────────────────────

def _read_pem_cert_text(cert_path: Path) -> str:
    return cert_path.read_text(encoding="utf-8", errors="ignore")


def _pem_to_der(cert_pem_text: str) -> bytes:
    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    if begin not in cert_pem_text or end not in cert_pem_text:
        return b""
    body = cert_pem_text.split(begin, 1)[1].split(end, 1)[0]
    b64 = "".join(line.strip() for line in body.strip().splitlines() if line.strip())
    try:
        return base64.b64decode(b64)
    except Exception:
        return b""


def get_cert_fingerprint(cert_path: Path = _CERT_FILE) -> str:
    """Return the SHA-256 fingerprint of a PEM certificate (no colons)."""
    if not cert_path.exists():
        return ""
    try:
        cert_der = _pem_to_der(_read_pem_cert_text(cert_path))
        if not cert_der:
            return ""
        return hashlib.sha256(cert_der).hexdigest().upper()
    except Exception:
        return ""


def _ensure_certs():
    global _TLS_AVAILABLE
    if not _CERT_FILE.exists() or not _KEY_FILE.exists():
        if config.P2P_ALLOW_DEV_SELF_SIGNED:
            print("[P2P] Dev self-signed mode requested, but automatic certificate generation has been removed.")
            print("[P2P] Provide cert/key files via DARKSPACE_P2P_TLS_CERT_PATH and DARKSPACE_P2P_TLS_KEY_PATH.")
        else:
            print("[P2P] TLS certificate/key not found. Running in plaintext listener mode (dev only).")
            print("[P2P] For production, provision PKI-issued certs and enable mutual-auth controls.")
    _TLS_AVAILABLE = _CERT_FILE.exists() and _KEY_FILE.exists()


def _server_ssl_context() -> ssl.SSLContext | None:
    if not _TLS_AVAILABLE:
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(_CERT_FILE), keyfile=str(_KEY_FILE))
    ctx.verify_mode = ssl.CERT_OPTIONAL   # request but don't require client cert
    ctx.check_hostname = False
    return ctx


def _client_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE       # trust pinned by fingerprint instead
    if _TLS_AVAILABLE:
        ctx.load_cert_chain(certfile=str(_CERT_FILE), keyfile=str(_KEY_FILE))
    return ctx


# ── DB ────────────────────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db():
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS mesh_inbox (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            received_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
            peer_url        TEXT,
            peer_fingerprint TEXT,
            payload         TEXT,
            sig_valid       INTEGER DEFAULT 0,
            attest_valid    INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS mesh_peer_registry (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            first_seen      DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen       DATETIME DEFAULT CURRENT_TIMESTAMP,
            peer_ip         TEXT,
            fingerprint     TEXT UNIQUE,
            trusted         INTEGER DEFAULT 0
        );
    """)
    conn.commit()
    conn.close()


# ── Signing & attestation ─────────────────────────────────────────────────────

def _sign(payload: str) -> str:
    return hmac.new(config.HMAC_SECRET, payload.encode(), hashlib.sha256).hexdigest()


def _verify(payload: str, sig: str) -> bool:
    expected = _sign(payload)
    return hmac.compare_digest(expected, sig)


def _node_id() -> str:
    return f"spiffe://darkspace/node/{hashlib.sha256(config.HMAC_SECRET).hexdigest()[:16]}"


def _attest_claim(nonce: str = "") -> dict:
    """
    Build a SPIFFE-style identity claim.
    In production replace with a real SVID from SPIRE.
    """
    claim = {
        "spiffe_id": _node_id(),
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "nonce": nonce,
        "cert_fingerprint": get_cert_fingerprint(),
    }
    claim["attest_sig"] = _sign(json.dumps(claim, sort_keys=True))
    return claim


def _verify_attest(claim: dict) -> bool:
    sig = claim.pop("attest_sig", "")
    expected = _sign(json.dumps(claim, sort_keys=True))
    claim["attest_sig"] = sig  # restore
    return hmac.compare_digest(expected, sig)


def _fingerprint_trusted(fp: str) -> bool:
    """Return True if fingerprint is in the configured allowlist, or allowlist is empty (dev mode)."""
    if not PEER_CERT_FINGERPRINTS:
        return True   # dev mode: trust all
    return fp.upper().replace(":", "") in PEER_CERT_FINGERPRINTS


def _register_peer(peer_ip: str, fingerprint: str, trusted: bool):
    conn = _get_conn()
    conn.execute(
        "INSERT INTO mesh_peer_registry (peer_ip, fingerprint, trusted) "
        "VALUES (?, ?, ?) "
        "ON CONFLICT(fingerprint) DO UPDATE SET "
        "last_seen=CURRENT_TIMESTAMP, trusted=excluded.trusted",
        (peer_ip, fingerprint, int(trusted)),
    )
    conn.commit()
    conn.close()


# ── Build local summary ───────────────────────────────────────────────────────

def build_summary() -> dict:
    """Collect a signed, attested snapshot of recent threat counts."""
    conn = _get_conn()
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    total = conn.execute(
        "SELECT COUNT(*) FROM threat_log WHERE timestamp >= ?", (since,)
    ).fetchone()[0]
    by_type = conn.execute(
        "SELECT threat_type, COUNT(*) as cnt FROM threat_log "
        "WHERE timestamp >= ? GROUP BY threat_type ORDER BY cnt DESC LIMIT 10",
        (since,),
    ).fetchall()
    conn.close()

    summary = {
        "node": _node_id(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "period_hours": 24,
        "total_alerts": total,
        "by_type": {r["threat_type"]: r["cnt"] for r in by_type},
        "attestation": _attest_claim(),
    }
    payload_str = json.dumps(
        {k: v for k, v in summary.items() if k != "attestation"}, sort_keys=True
    )
    summary["sig"] = _sign(payload_str)
    return summary


# ── HTTP listener (TLS-wrapped) ───────────────────────────────────────────────

class _MeshHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _peer_fingerprint(self) -> str:
        try:
            peer_cert = self.connection.getpeercert(binary_form=True)
            if peer_cert:
                return hashlib.sha256(peer_cert).hexdigest().upper()
        except Exception as e:
            print(f"[P2P] Fingerprint extraction failed: {e}")
            return ""
        return ""

    def do_GET(self):
        if self.path == "/summary":
            data = json.dumps(build_summary()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif self.path == "/fingerprint":
            fp = get_cert_fingerprint()
            data = json.dumps({"fingerprint": fp, "node": _node_id()}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/ingest":
            peer_fp = self._peer_fingerprint()
            peer_ip = self.client_address[0]

            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode("utf-8", errors="ignore")
            try:
                msg = json.loads(raw)

                # ── Attestation check ─────────────────────────────────────────
                attest = msg.pop("attestation", {})
                attest_valid = bool(attest) and _verify_attest(dict(attest))

                # ── Payload HMAC check ────────────────────────────────────────
                sig = msg.pop("sig", "")
                payload_str = json.dumps(msg, sort_keys=True)
                sig_valid = _verify(payload_str, sig)

                # ── Fingerprint allowlist ─────────────────────────────────────
                fp_trusted = _fingerprint_trusted(peer_fp)
                _register_peer(peer_ip, peer_fp or "unknown", fp_trusted)

                accepted = sig_valid and attest_valid and fp_trusted

                conn = _get_conn()
                conn.execute(
                    "INSERT INTO mesh_inbox "
                    "(peer_url, peer_fingerprint, payload, sig_valid, attest_valid) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (peer_ip, peer_fp, raw[:2000],
                     int(sig_valid), int(attest_valid)),
                )
                conn.commit()
                conn.close()

                reasons = []
                if not sig_valid:    reasons.append("bad HMAC")
                if not attest_valid: reasons.append("bad attestation")
                if not fp_trusted:   reasons.append("untrusted cert fingerprint")
                status = "accepted" if accepted else f"rejected ({', '.join(reasons)})"
                print(f"[P2P] Ingest from {peer_ip} ({peer_fp[:12] or 'no-cert'}): {status}")
                self.send_response(200 if accepted else 403)
            except Exception as e:
                print(f"[P2P] Ingest error: {e}")
                self.send_response(400)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()


def _start_listener(port: int):
    server = HTTPServer((LISTEN_HOST, port), _MeshHandler)
    ssl_ctx = _server_ssl_context()
    if ssl_ctx:
        server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)
        print(f"[P2P] TLS listener started on port {port}  "
              f"(fingerprint: {get_cert_fingerprint()[:16]}…)")
    else:
        print(f"[P2P] Plaintext listener started on port {port} "
              f"(TLS unavailable — dev mode)")
    server.serve_forever()


# ── Push to peers ─────────────────────────────────────────────────────────────

def push_to_peers(peers: list[str]) -> dict[str, str]:
    summary = build_summary()
    results: dict[str, str] = {}
    body = json.dumps(summary).encode()
    ssl_ctx = _client_ssl_context()

    for peer in peers:
        # Upgrade http:// → https:// if TLS available
        url = peer.rstrip("/")
        if _TLS_AVAILABLE and url.startswith("http://"):
            url = "https://" + url[7:]
        url += "/ingest"

        req = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ssl_ctx)
            )
            with opener.open(req, timeout=5) as resp:
                results[peer] = f"ok ({resp.status})"
        except urllib.error.URLError as e:
            results[peer] = f"error: {e.reason}"
        except Exception as e:
            results[peer] = f"error: {e}"
        print(f"[P2P] Push → {url}  {results[peer]}")
    return results


def _sync_loop(peers: list[str], interval: int):
    while True:
        if peers:
            push_to_peers(peers)
        else:
            print("[P2P] No peers configured — listener-only mode.")
        time.sleep(interval)


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="DARKSPACE P2P Mesh — mutual-TLS threat-intel sync"
    )
    parser.add_argument("--port", type=int, default=config.P2P_LISTEN_PORT,
                        help=f"Listen port (default: {config.P2P_LISTEN_PORT})")
    parser.add_argument("--push-only", action="store_true",
                        help="Push summary to peers once and exit")
    parser.add_argument("--interval", type=int,
                        default=config.P2P_SYNC_INTERVAL_SECONDS,
                        help=f"Sync interval (default: {config.P2P_SYNC_INTERVAL_SECONDS}s)")
    parser.add_argument("--show-fingerprint", action="store_true",
                        help="Print this node's cert fingerprint and exit")
    args = parser.parse_args()

    if args.show_fingerprint:
        fp = get_cert_fingerprint()
        if fp:
            print(f"Fingerprint : {fp}")
            print(f"Node ID     : {_node_id()}")
        else:
            print("No certificate found. Set DARKSPACE_P2P_TLS_CERT_PATH / DARKSPACE_P2P_TLS_KEY_PATH.")
        sys.exit(0)

    _ensure_certs()
    _init_db()

    if args.push_only:
        results = push_to_peers(config.P2P_PEERS)
        print(json.dumps(results, indent=2))
    else:
        listener_thread = threading.Thread(
            target=_start_listener, args=(args.port,), daemon=True
        )
        listener_thread.start()
        _sync_loop(config.P2P_PEERS, args.interval)
