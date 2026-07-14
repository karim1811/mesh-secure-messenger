"""mesh_transport.py - Transport MESH via Meshtastic (LoRa) (etape 5).

Couche transport qui remplace le socket TCP par la radio LoRa. Le blob chiffre
(de crypto_utils, deja illisible) est encapsule dans un message Meshtastic
canal "secondary" (texte base64). Aucun message en clair ne sort du module crypto.

Contraintes LoRa:
  - ~200-220 octets max par message texte Meshtastic (on fragmente au-dela).
  - debit faible, latence haute : c'est un transport off-grid, pas du chat rapide.
  - portée km (campagne) sans infra : chaque node relaie (mesh).

Usage:
  python mesh_transport.py send <blob_base64> [--port COM3]
  python mesh_transport.py recv                  # boucle, affiche blobs recus

Le relais est remplace par le MESH lui-meme : aucun serveur central.
"""
import sys, os, base64, time, threading, json

MAX_CHUNK = 200  # octets par fragment texte Meshtastic (marge sur la limite ~220)


def _frag(blob_b64: str):
    """Fragmente un blob base64 en morceaux <= MAX_CHUNK avec en-tete."""
    out = []
    n = len(blob_b64)
    i = 0
    idx = 0
    total = (n + MAX_CHUNK - 1) // MAX_CHUNK
    while i < n:
        chunk = blob_b64[i:i + MAX_CHUNK]
        # format: MESH|<idx>/|total|chunk
        out.append(f"MESH|{idx}|{total}|{chunk}")
        i += MAX_CHUNK
        idx += 1
    return out


def _reassemble(frags: dict, total: int) -> str:
    if len(frags) < total:
        return None
    return "".join(frags[i] for i in sorted(frags))


class MeshTransport:
    """Encapsule un node Meshtastic. Si aucun node, mode SIM (loopback local)."""

    def __init__(self, port=None, channel_index=1):
        self.port = port
        self.channel_index = channel_index
        self._iface = None
        self._buf = {}            # (from_id) -> {idx: chunk, total: int}
        self._lock = threading.Lock()
        self._callbacks = []
        self.sim = False
        self._connect()

    def _connect(self):
        try:
            from meshtastic import serial_interface, tcp_interface
            from pubsub import pub
            if self.port and self.port.startswith("tcp"):
                self._iface = tcp_interface.TCPInterface(hostname=self.port.split("://")[1])
            else:
                self._iface = serial_interface.SerialInterface(devPath=self.port)
            # meshtastic >=2 publie les messages texte via pubsub
            pub.subscribe(self._on_rx, "meshtastic.receive.text")
        except Exception as e:
            print(f"[!] Meshtastic indisponible ({e}) -> mode SIM (loopback).")
            self.sim = True

    def _on_rx(self, packet=None):
        if packet is None:
            return
        try:
            txt = packet["decoded"]["text"]
        except Exception:
            return
        if not txt.startswith("MESH|"):
            return
        parts = txt.split("|", 3)
        if len(parts) < 4:
            return
        idx = int(parts[1]); total = int(parts[2]); chunk = parts[3]
        frm = packet.get("fromId", "peer")
        with self._lock:
            d = self._buf.setdefault(frm, {"total": total, "chunks": {}})
            d["chunks"][idx] = chunk
            blob = _reassemble(d["chunks"], total)
        if blob:
            for cb in self._callbacks:
                cb(blob)

    def on_receive(self, cb):
        self._callbacks.append(cb)

    def send(self, blob_b64: str):
        frags = _frag(blob_b64)
        if self.sim:
            # loopback : on re-injecte comme si recu du mesh
            full = "".join(f.split("|", 3)[3] for f in frags)
            for cb in self._callbacks:
                cb(full)
            return len(frags)
        for f in frags:
            self._iface.sendText(f, channel_index=self.channel_index)
            time.sleep(0.3)  # throttle LoRa
        return len(frags)

    def close(self):
        if self._iface and not self.sim:
            self._iface.close()


def main():
    if len(sys.argv) < 2:
        print("Usage: python mesh_transport.py {send <blob>|recv} [--port COMx]")
        sys.exit(1)
    cmd = sys.argv[1]
    port = None
    if "--port" in sys.argv:
        port = sys.argv[sys.argv.index("--port") + 1]
    t = MeshTransport(port=port)
    if cmd == "send":
        blob = sys.argv[2] if len(sys.argv) > 2 else ""
        n = t.send(blob)
        print(f"[+] {n} fragment(s) LoRa emis (mode {'SIM' if t.sim else 'LORA'})")
    elif cmd == "recv":
        print("[*] Ecoute du mesh (Ctrl+C pour quitter)...")
        ev = threading.Event()
        def cb(blob):
            print(f"[mesh] blob recu ({len(blob)} chars): {blob[:60]}...")
        t.on_receive(cb)
        try:
            while not ev.wait(1):
                pass
        except KeyboardInterrupt:
            pass
        finally:
            t.close()
    else:
        print("Commande inconnue:", cmd)


if __name__ == "__main__":
    main()
