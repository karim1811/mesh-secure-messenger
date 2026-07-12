"""
server.py - Relais localhost (etape 2, POC).

Recoit les messages DEJA chiffres (blobs base64) et les route vers l'autre
client connecte. Le serveur ne DECRYPTE jamais : il ne voit que du texte
illisible. C'est un hub local pour tester le transport socket sans infra reelle.

Amelioration: memorize le dernier message 'pub' de chaque client et le
renvoie a tout nouveau client connecte (peu importe l'ordre de connexion).

Usage:
  python server.py            # ecoute 127.0.0.1:9001
  python server.py 9002       # port custom
"""
import sys
import socket
import threading
import json

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9001

clients = {}          # conn -> True (ensemble des clients connectes)
latest_pub = {}       # conn -> bytes (dernier blob 'pub' pour rattrapage)
lock = threading.Lock()


def relay(src_conn):
    """Thread par client : lit les messages et les diffuse aux AUTRES clients."""
    while True:
        try:
            data = src_conn.recv(65536)
        except Exception:
            break
        if not data:
            break
        # memorise le dernier 'pub' pour les nouveaux arrives
        try:
            msg = json.loads(data.decode("utf-8").split("\n")[0])
            if msg.get("type") == "pub":
                with lock:
                    latest_pub[src_conn] = data
        except Exception:
            pass
        with lock:
            others = [c for c in clients if c is not src_conn]
        for c in others:
            try:
                c.sendall(data)
            except Exception:
                pass
    with lock:
        clients.pop(src_conn, None)
        latest_pub.pop(src_conn, None)
    try:
        src_conn.close()
    except Exception:
        pass
    print(f"[-] Un client s'est deconnecte ({len(clients)} restant(s))")


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(8)
    print(f"[*] Relais localhost en ecoute sur {HOST}:{PORT}")
    print("    Lance 2 clients (python client.py alice / bob), puis discute.")
    try:
        while True:
            conn, addr = srv.accept()
            with lock:
                # rattrapage: on envoie les 'pub' deja connus au nouveau client
                backlog = [latest_pub[c] for c in clients if c in latest_pub]
                clients[conn] = True
            for pub in backlog:
                try:
                    conn.sendall(pub)
                except Exception:
                    pass
            print(f"[+] Connexion de {addr} ({len(clients)} connecte(s))")
            t = threading.Thread(target=relay, args=(conn,), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[*] Arret du relais.")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
