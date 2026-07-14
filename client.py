"""
client.py - Messagerie chiffree E2E multi-pair, transport = socket TCP localhost.

La couche crypto (crypto_utils) est INCHANGEE. On remplace le stockage des cles
par un chiffrement scrypt+Fernet et on passe d'une session 1:1 a un dict de
sessions par pair (multi-pair). Aucun message en clair ne traverse le reseau :
seul un blob base64 (deja chiffre + signe par crypto_utils) sort de la machine.

Usage:
  terminal 1: python server.py
  terminal 2: python client.py alice
  terminal 3: python client.py bob
  terminal 4: python client.py carol

Messages:
  salut                     -> diffuse a tous les pairs connectes
  @bob salut bob            -> destinataire unique (("to": "bob"))
  quit                      -> quitte
"""
import sys
import os
import json
import socket
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crypto_utils import (generate_identity, pubkey_bundle, load_remote_pubkeys,
                          derive_session_key, encrypt_message, decrypt_message)
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet
import base64, getpass

import socks as pysocks   # pysocks : proxy SOCKS5 pour joindre les .onion via Tor

HOST = "127.0.0.1"
PORT = 9001
# Proxy SOCKS de Tor. 9050 = Tor (Expert Bundle / service), 9150 = Tor Browser.
TOR_PROXY_HOST = "127.0.0.1"
TOR_PROXY_PORT = 9050

BASE = os.path.dirname(os.path.abspath(__file__))


def path(*a):
    return os.path.join(BASE, *a)


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """scrypt -> 32 octets -> cle Fernet (URL-safe base64)."""
    kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


# --- stockage SECURISE des cles privees (chiffrees par passphrase) ---
def store_identity(me):
    ident = generate_identity(me)
    raw = {
        "enc_priv": ident["enc_priv"].private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption()).hex(),
        "sig_priv": ident["sig_priv"].private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption()).hex(),
    }
    passphrase = getpass.getpass(f"Passphrase pour chiffrer la cle de {me}: ")
    salt = os.urandom(16)
    key = _derive_key(passphrase, salt)
    token = Fernet(key).encrypt(json.dumps(raw).encode("utf-8"))
    json.dump({"salt": salt.hex(), "v": 1, "data": token.decode("ascii")},
              open(path(f"id_{me}.json"), "w"))


def load_identity(me):
    blob = json.load(open(path(f"id_{me}.json")))
    passphrase = getpass.getpass(f"Passphrase pour {me}: ")
    key = _derive_key(passphrase, bytes.fromhex(blob["salt"]))
    raw = json.loads(Fernet(key).decrypt(blob["data"].encode("ascii")))
    enc_priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(raw["enc_priv"]))
    sig_priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(raw["sig_priv"]))
    return {
        "name": me,
        "enc_priv": enc_priv,
        "enc_pub": enc_priv.public_key(),
        "sig_priv": sig_priv,
        "sig_pub": sig_priv.public_key(),
    }


# --- annuaire de pubkeys (PUBLIQUES, non sensibles) pour chiffrer vers un pair offline ---
def _b64pub(pubkey) -> str:
    from cryptography.hazmat.primitives import serialization as _s
    return pubkey.public_bytes(_s.Encoding.Raw, _s.PublicFormat.Raw).hex()


def load_peers() -> dict:
    p = path("peers.json")
    if not os.path.exists(p):
        return {}
    try:
        return json.load(open(p))
    except Exception:
        return {}


def save_peers(peers: dict):
    json.dump(peers, open(path("peers.json"), "w"))


def make_socket(host, port, tor_port=TOR_PROXY_PORT):
    """Cree le socket de transport.

    - Si l'hote se termine par .onion : on passe par le proxy SOCKS5 de Tor
      (le DNS est resolu DANS Tor, impossible a faire en clair depuis l'exterieur).
    - Sinon : socket TCP classique (localhost ou LAN).
    """
    if host.endswith(".onion"):
        s = pysocks.socksocket()
        s.set_proxy(pysocks.SOCKS5, TOR_PROXY_HOST, tor_port)
        s.connect((host, port))
        return s
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    return s


def main():
    if len(sys.argv) < 2:
        print("Usage: python client.py <nom> [host] [port] [--tor-port 9050]")
        print("  host peut etre un .onion -> connexion via Tor SOCKS automatique")
        sys.exit(1)
    me = sys.argv[1]
    # parse args positionnels + option --tor-port
    positional = [a for a in sys.argv[2:] if not a.startswith("--")]
    opts = sys.argv[2:]
    tor_port = TOR_PROXY_PORT
    if "--tor-port" in opts:
        i = opts.index("--tor-port")
        if i + 1 < len(opts):
            tor_port = int(opts[i + 1])
    host = positional[0] if len(positional) > 0 else HOST
    port = int(positional[1]) if len(positional) > 1 else PORT
    idfile = path(f"id_{me}.json")

    if not os.path.exists(idfile):
        print(f"[*] Generation de l'identite pour {me}...")
        store_identity(me)
    ident = load_identity(me)

    # --- connexion au relais (localhost direct OU .onion via Tor) ---
    via_tor = host.endswith(".onion")
    sock = make_socket(host, port, tor_port=tor_port)
    if via_tor:
        print(f"[+] Connecte au relais Tor .onion {host}:{port} (via SOCKS {TOR_PROXY_HOST}:{tor_port})")
    else:
        print(f"[+] Connecte au relais {host}:{port}")

    # publie notre bundle (fini les fichiers)
    bundle = pubkey_bundle(ident)
    sock.sendall((json.dumps({"type": "pub", "bundle": bundle}) + "\n").encode("utf-8"))

    # sessions E2E par pair
    sessions = {}          # name -> {"key", "sig_pub"}
    peers = load_peers()   # name -> {"enc_pub","sig_pub"} persistes (publiques)
    ilock = threading.Lock()
    incoming = []
    plock = threading.Lock()
    pending = []

    # derive une session E2E pour un pair (live d'abord, sinon pubkey persiste)
    def session_for(name):
        with ilock:
            if name in sessions:
                return sessions[name]
        if name in peers:
            enc_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(peers[name]["enc_pub"]))
            sig_pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(peers[name]["sig_pub"]))
            key = derive_session_key(ident["enc_priv"], enc_pub)
            return {"key": key, "sig_pub": sig_pub}
        return None

    def handle(msg):
        if msg.get("type") == "pub":
            remote = load_remote_pubkeys(msg["bundle"])
            key = derive_session_key(ident["enc_priv"], remote["enc_pub"])
            with ilock:
                sessions[remote["name"]] = {"key": key, "sig_pub": remote["sig_pub"]}
                peers[remote["name"]] = {"enc_pub": _b64pub(remote["enc_pub"]),
                                         "sig_pub": _b64pub(remote["sig_pub"])}
                save_peers(peers)
                incoming.append(("sys", f"Session E2E active avec {remote['name']}"))
        elif msg.get("type") == "msg":
            frm = msg.get("from")
            sess = session_for(frm)  # live d'abord, puis peers persistes (offline)
            if not sess:
                with ilock:
                    incoming.append(("!", f"message de {frm} sans session E2E (pubkey inconnue)"))
                return
            try:
                txt = decrypt_message(sess["key"], msg["blob"], sess["sig_pub"])
                with ilock:
                    incoming.append((frm, txt))
            except Exception as e:
                with ilock:
                    incoming.append(("!", f"message illisible / mauvais expediteur: {e}"))

    def receiver():
        buf = b""
        while True:
            try:
                chunk = sock.recv(65536)
            except Exception:
                break
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line.decode("utf-8"))
                except Exception:
                    continue
                handle(msg)

    def input_loop():
        try:
            for raw in sys.stdin:
                with plock:
                    pending.append(raw.rstrip("\n"))
        except Exception:
            pass

    t = threading.Thread(target=receiver, daemon=True)
    t.start()
    ti = threading.Thread(target=input_loop, daemon=True)
    ti.start()

    print(f"\n[*] En attente des correspondants ({me})...")
    tty = sys.stdout.isatty()
    prompt = f"[{me}] "

    def redraw_prompt():
        if tty:
            print(prompt, end="", flush=True)

    if tty:
        print(prompt, end="", flush=True)
    while True:
        with ilock:
            while incoming:
                name, txt = incoming.pop(0)
                if tty:
                    print("\r" + " " * 60 + "\r", end="")
                else:
                    print()
                print(f"[{name}] {txt}")
                redraw_prompt()
        with plock:
            while pending:
                line = pending.pop(0)
                if not tty:
                    print(f"[{me}] {line}")
                if line.lower() == "quit":
                    sock.close()
                    return
                if not line.strip():
                    redraw_prompt()
                    continue
                target = None
                body = line
                if line.startswith("@"):
                    parts = line[1:].split(" ", 1)
                    target = parts[0]
                    body = parts[1] if len(parts) > 1 else ""
                with ilock:
                    live = list(sessions.keys())
                # on peut chiffrer vers un pair meme offline (pubkey persiste)
                if target:
                    s = session_for(target)
                    if s:
                        blob = encrypt_message(s["key"], body, ident["sig_priv"])
                        sock.sendall((json.dumps(
                            {"type": "msg", "to": target, "from": me, "blob": blob}) + "\n").encode())
                    else:
                        with ilock:
                            incoming.append(("!", f"jamais croise @{target} (pubkey inconnue)"))
                else:
                    if not live and not peers:
                        with ilock:
                            incoming.append(("!", "aucun pair connu pour diffuser"))
                    for p in set(live) | set(peers.keys()):
                        s = session_for(p)
                        if not s:
                            continue
                        blob = encrypt_message(s["key"], body, ident["sig_priv"])
                        sock.sendall((json.dumps(
                            {"type": "msg", "to": p, "from": me, "blob": blob}) + "\n").encode())
                redraw_prompt()
        time.sleep(0.05)


if __name__ == "__main__":
    main()
