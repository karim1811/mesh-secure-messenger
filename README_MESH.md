# Mesh Secure Messenger - Transport Meshtastic / LoRa (etape 5)

Le relais central (server.py / Tor) est remplace par un vrai MESH radio LoRa.
Chaque node ESP32 relaie les messages : aucune infra, portee km (campagne),
fonctionne OFF-GRID (pas d'internet).

Fonctionnement:
- `mesh_transport.py` prend un blob DEJA chiffre (crypto_utils) et l'encapsule
  dans des messages Meshtastic (texte base64, canal secondaire).
- Limite LoRa ~200-220 octets/message -> fragmentation automatique en morceaux
  `MESH|<idx>|<total>|<chunk>`, reassembles a la reception.
- Aucun message en clair ne sort du module crypto : le mesh ne voit que du
  base64 illisible.

Hardware necessaire:
- Un node Meshtastic (ex: Heltec WiFi LoRa 32, T-Beam, RAK) flashé Meshtastic.
- Branche en USB (COMx Windows) ou connexion TCP (sur le meme reseau).

Usage:
```bash
# Windows, node sur COM3
python mesh_transport.py send "<blob_base64>" --port COM3
python mesh_transport.py recv --port COM3

# Linux/Mac
python mesh_transport.py send "<blob_base64>" --port /dev/ttyUSB0
```

Sans hardware: le module bascule en mode SIM (loopback local) -> on peut
tester la fragmentation/reassemblement sans radio.

Integration etape suivante:
- Brancher mesh_transport dans client.py : si `host == "mesh"`, utiliser
  MeshTransport au lieu du socket. Le chiffrement E2E reste IDENTIQUE.

Note API: meshtastic >=2 publie les messages via `pubsub`
(`meshtastic.receive.text`). `sendText()` (PascalCase) pour emettre.
