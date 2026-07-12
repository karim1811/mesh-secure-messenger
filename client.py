"""
client.py - Messagerie chiffree E2E, transport = socket TCP localhost (etape 2).

La couche crypto (crypto_utils) est INCHANGEE. On remplace uniquement le
transport fichier par un socket vers le relais local (server.py).

Aucun message en clair ne traverse le reseau : seul un blob base64 (deja
chiffre + signe par crypto_utils) sort de la machine locale.

Usage:
  terminal 1: python server.py
  terminal 2: python client.py alice
  terminal 3: python client.py bob
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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HOST = "127.0.0.1"
PORT = 9001

BASE = os.path.dirname(os.path.abspath(__file__))


def path(*a):
    return os.path.join(BASE, *a)


def main():
    if len(sys.argv) < 2:
        print("Usage: python client.py <nom> [host] [port]")
        sys.exit(1)
    me = sys.argv[1]
    host = sys.argv[2] if len(sys.argv) > 2 else HOST
    port = int(sys.argv[3]) if len(sys.argv) > 3 else PORT
    idfile = path(f"id_{me}.json")

    # --- identite (generee une fois, cles privees jamais partagees) ---
    if not os.path.exists(idfile):
        print(f"[*] Generation de l'identite pour {me}...")
        store_identity(me)
    ident = load_identity(me)

    # --- connexion au relais localhost ---
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    print(f"[+] Connecte au relais {host}:{port}")

    # --- on publie notre cle publique via le reseau (fini les fichiers) ---
    bundle = pubkey_bundle(ident)
    sock.sendall((json.dumps({"type": "pub", "bundle": bundle}) + "\n").encode("utf-8"))

    # --- etat partage avec les threads ---
    remote = {}
    session = {}
    ready = threading.Event()
    incoming = []                     # file des messages recus (thread-safe)
    ilock = threading.Lock()
    pending = []                      # lignes saisies par l'utilisateur (Enter)
    plock = threading.Lock()

    def handle(msg):
        if msg.get("type") == "pub":
            remote.clear()
            remote.update(load_remote_pubkeys(msg["bundle"]))
            session_key = derive_session_key(ident["enc_priv"], remote["enc_pub"])
            session.clear()
            session["key"] = session_key
            ready.set()
            with ilock:
                incoming.append(("sys", f"Correspondant detecte: {remote['name']} -> session E2E active"))
        elif msg.get("type") == "msg":
            if not ready.is_set():
                return
            try:
                txt = decrypt_message(session["key"], msg["blob"], remote["sig_pub"])
                with ilock:
                    incoming.append((remote["name"], txt))
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
        """Lit les lignes saisies (marche terminal reel ET pipe)."""
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

    print(f"\n[*] En attente du correspondant ({me})...")
    ready.wait()
    print(f"\n=== Session E2E active ({me} <-> {remote.get('name')}) ===")
    print("Tape un message + Entree pour envoyer. 'quit' pour quitter.\n")

    tty = sys.stdout.isatty()
    prompt = f"[{me}] "
    if tty:
        print(prompt, end="", flush=True)
    while True:
        # afficher les messages entrants
        with ilock:
            while incoming:
                name, txt = incoming.pop(0)
                if tty:
                    width = len(prompt) + 20
                    print("\r" + " " * width + "\r", end="")
                else:
                    print()
                print(f"[{name}] {txt}")
                if tty:
                    print(prompt, end="", flush=True)
        # traiter les lignes saisies
        with plock:
            while pending:
                line = pending.pop(0)
                if not tty:
                    print(f"[{me}] {line}")
                if line.lower() == "quit":
                    sock.close()
                    return
                if line.strip():
                    blob = encrypt_message(session["key"], line, ident["sig_priv"])
                    sock.sendall((json.dumps({"type": "msg", "blob": blob}) + "\n").encode("utf-8"))
                if tty:
                    print(prompt, end="", flush=True)
        time.sleep(0.05)


# --- stockage POC des cles privees (fichier local, clair -> remplacer par passphrase) ---
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
    json.dump(raw, open(path(f"id_{me}.json"), "w"))


def load_identity(me):
    raw = json.load(open(path(f"id_{me}.json")))
    enc_priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(raw["enc_priv"]))
    sig_priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(raw["sig_priv"]))
    return {
        "name": me,
        "enc_priv": enc_priv,
        "enc_pub": enc_priv.public_key(),
        "sig_priv": sig_priv,
        "sig_pub": sig_priv.public_key(),
    }


if __name__ == "__main__":
    main()
