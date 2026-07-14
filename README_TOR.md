# Mesh Secure Messenger - Transport Tor .onion (etape 3)

Le chiffrement E2E (crypto_utils) est INCHANGE. On ajoute Tor comme transport :
le relais devient un service onion inaccessible sans Tor, et les clients
peuvent se connecter a un .onion via le proxy SOCKS de Tor.

Avantage : l'IP du relais n'est jamais connue des correspondants. Meme l'hebergeur
du relais ne voit que des blobs chiffres (AES-256-GCM + signature Ed25519).

## 1. Installer Tor
- Windows : Telecharger "Tor Expert Bundle" (pas le navigateur) sur torproject.org
  et decompresser, OU installer Tor Browser (le SOCKS tourne sur 9150).
- Linux : `sudo apt install tor`  (service sur 9050)
- Mac : `brew install tor`

## 2. Lancer le relais + Tor
```bash
# terminal 1 : relais local (INCHANGE, tourne sur 127.0.0.1:9001)
python server.py

# terminal 2 : Tor avec le torrc fourni
tor -f torrc.example
```
Tor cree le dossier `hidden_service/` et y ecrit `hostname`
(ex: `abcexemple1234567890abcdef.onion`).

## 3. Donner le .onion a ton correspondant
Envoie-lui le contenu de `hidden_service/hostname` (le .onion).
Il n'a PAS besoin de connaitre ton IP.

## 4. Les clients se connectent en .onion
```bash
# correspondant A (toi, derriere Tor)
python client.py alice abcexemple1234567890abcdef.onion 9001

# correspondant B (lui, derriere Tor aussi)
python client.py bob  abcexemple1234567890abcdef.onion 9001
```
Le client detecte automatiquement le suffixe `.onion` et route via le proxy
SOCKS de Tor (port 9050 par defaut, ou 9150 si tu utilises Tor Browser).
Pour changer le port SOCKS :
```bash
python client.py alice <toto>.onion 9001 --tor-port 9150
```

## SECURITE
- Le relais reste un hub : il route les blobs mais ne peut pas les lire.
- Ton IP reste cachee derriere Tor (le correspondant ne voit que le .onion).
- Les cles privees sont toujours en clair dans id_<nom>.json (POC).
  En prod : chiffrer ce fichier avec une passphrase (scrypt/argon2).
- Pour un vrai reseau mesh decentralise, voir l'etape Meshtastic (LoRa).
