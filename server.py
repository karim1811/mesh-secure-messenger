"""
server.py - Relais localhost multi-pair avec buffer offline (etape 3, POC).

- Diffuse les messages DEJA chiffres (blobs base64) aux destinataires.
- Le serveur ne DECRYPTE jamais : il ne voit que du texte illisible.
- Memoire : dernier 'pub' de chaque client connecte (rattrapage a la connexion).
- PERSISTANCE : si le destinataire est deconnecte, le message est bufferise
  et renvoye quand il se reconnecte (offline = il recoit ses messages plus tard).
- Broadcast (sans @cible) : envoye aux connectes + bufferise vers les pairs
  deja connus (vus au moins une fois).

Usage:
  python server.py            # ecoute 127.0.0.1:9001
  python server.py 9002       # port custom
"""
import sys
import socket
import threading
import json
import os

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9001

LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server_relay.log")


def log(*a):
    try:
        with open(LOG, "a") as f:
            f.write(" ".join(str(x) for x in a) + "\n")
            f.flush()
    except Exception:
        pass


# conn -> {"name": str|None}
clients = {}
# nom -> [bytes] messages offlines en attente
offline = {}
# nom -> bytes (dernier blob 'pub' connu, persiste apres deconnexion pour rattrapage)
known_pubs = {}
# ensemble des noms deja rencontres (pour bufferiser le broadcast vers offline connus)
known = set()
lock = threading.Lock()


def relay(src_conn):
    buf = b""
    while True:
        try:
            chunk = src_conn.recv(65536)
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
            _route(src_conn, line + b"\n", msg)
    with lock:
        name = clients.get(src_conn, {}).get("name", "client")
        clients.pop(src_conn, None)
    try:
        src_conn.close()
    except Exception:
        pass
    log("[-]", name, "deconnecte", len(clients), "restant(s)")


def _route(src_conn, raw, msg):
    with lock:
        name = clients.get(src_conn, {}).get("name")
    log("RECV", repr(name), msg.get("type"), "to=", msg.get("to"))
    if msg.get("type") == "pub":
        nm = msg["bundle"]["name"]
        with lock:
            clients[src_conn]["name"] = nm
            known_pubs[nm] = raw
            known.add(nm)
            others = [c for c in clients if c is not src_conn]
            pend = offline.pop(nm, [])
        for c in others:
            try:
                c.sendall(raw)
            except Exception:
                pass
        for m in pend:
            try:
                src_conn.sendall(m)
                log("[LIVRE] 1 msg offline ->", nm)
            except Exception as e:
                log("[LIVRE-ERR]", e)
        return

    if msg.get("type") == "msg":
        with lock:
            to = msg.get("to")
            if to:
                targets = [c for c, info in clients.items() if info.get("name") == to]
                if not targets:
                    offline.setdefault(to, []).append(raw)
                    log("[BUFFER] msg prive ->", to, "(offline)")
                    return
            else:
                targets = [c for c in clients if c is not src_conn]
                with lock:
                    connected_names = {clients[c].get("name") for c in clients if c is not src_conn}
                off_peers = [n for n in known if n != name and n not in connected_names]
                for n in off_peers:
                    offline.setdefault(n, []).append(raw)
                if off_peers:
                    log("[BUFFER] broadcast -> offline", off_peers)
        for c in targets:
            try:
                c.sendall(raw)
            except Exception:
                pass


def main():
    if os.path.exists(LOG):
        try:
            os.remove(LOG)
        except Exception:
            pass
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(16)
    log("[*] Relais multi-pair en ecoute sur", HOST, PORT)
    print(f"[*] Relais localhost multi-pair en ecoute sur {HOST}:{PORT}")
    print("    Lance plusieurs clients (python client.py alice / bob / carol).")
    try:
        while True:
            conn, addr = srv.accept()
            with lock:
                backlog = list(known_pubs.values())
                clients[conn] = {"name": None}
            for pub in backlog:
                try:
                    conn.sendall(pub)
                except Exception:
                    pass
            print(f"[+] Connexion de {addr} ({len(clients)} connecte(s))")
            log("[+] connexion", addr, len(clients), "connecte(s)")
            t = threading.Thread(target=relay, args=(conn,), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[*] Arret du relais.")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
