# mesh-secure-messenger

Messagerie chiffree de bout en bout (E2E) + transport futur Meshtastic / .onion.

## But
Communication libre et chiffree, sans infrastructure centrale controllable.
- Couche chiffrement independante du transport (internet, radio LoRa, onion).
- Aucun message en clair ne sort du module crypto_utils.

## Primitives
- X25519 : echange de cles (ECDH -> meme secret des deux cotes)
- AES-256-GCM : chiffrement des messages + integrite
- Ed25519 : signature (anti-usurpation / MITM)

## Etat
- [x] Chiffrement E2E fonctionnel (teste: ECDH, decryptage, anti-MITM)
- [x] Transport fichier (POC etape 1)
- [x] Transport socket localhost via relais local (etape 2): `server.py` + `client.py`
- [x] Transport .onion (Tor hidden service): client route via SOCKS Tor,
      config `torrc.example`, doc `README_TOR.md`
- [x] Clés privees chiffrees par passphrase (scrypt + Fernet) + multi-pair
- [x] Wallet crypto non-custodial (etape 4): `wallet.py`, doc `README_WALLET.md`
- [x] Transport Meshtastic / LoRa (etape 5): `mesh_transport.py`, doc `README_MESH.md`
      (fragmentation + mode SIM; hardware requis pour le vrai mesh radio)

## Lancer (etape 2 - socket localhost)
3 fenetres terminal dans ce dossier:
```
python server.py            # relais localhost 127.0.0.1:9001
python client.py alice      # client 1 (localhost)
python client.py bob        # client 2 (localhost)
```

Pour tester avec un AUTRE utilisateur sur le meme reseau (LAN):
- l'autre lance `python server.py` sur sa machine (ou vous partagez un relais)
- il faut que le client vise l'IP de la machine qui heberge le relais:
```
python client.py bob 192.168.1.42     # host = IP du relais, port par defaut 9001
python client.py bob 192.168.1.42 9002  # host + port custom
```
Note: le relais localhost est un POC. Pour un vrai usage entre machines, le
relais doit tourner sur une machine jointe (LAN ou VPS) et les ports ouverts.
Le chiffrement reste identique: le relais ne voit que des blobs illisibles.

## SECURITE (a durcir avant usage reel)
- Les cles privees sont stockees en clair dans id_<nom>.json (POC uniquement).
  En prod: chiffrer le fichier avec un mot de passe (scrypt/argon2).
- Le transport socket localhost est un POC local: un tiers sur la meme machine
  peut sniffer le localhost. Passer au transport .onion + chiffrement déjà OK.

## Legal
Tor, chiffrement et consultation de contenus legaux sont legaux en France/EU.
Ne jamais telecharger/executer de contenu illegal.
