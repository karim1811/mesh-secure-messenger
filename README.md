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

## Etat (etape 1)
- [x] Chiffrement E2E fonctionnel (teste: ECDH, decryptage, anti-MITM)
- [x] Client CLI local (transport = fichiers inbox, POC)
- [ ] Transport socket localhost
- [ ] Transport .onion (Tor hidden service)
- [ ] Transport Meshtastic (noeud ESP32 LoRa) -- quand carte dispo
- [ ] Wallet crypto non-custodial (web3.py) -- etape ulterieure

## Lancer (test local)
Deux fenetres terminal dans ce dossier:
```
python client.py alice
python client.py bob
```
Au 1er lancement chaque user publie sa cle dans pub_<nom>.json.
Pose les deux fichiers pub dans le dossier, relance: la session E2E s'active.

## SECURITE (a durcir avant usage reel)
- Les cles privees sont stockees en clair dans id_<nom>.json (POC uniquement).
  En prod: chiffrer le fichier avec un mot de passe (scrypt/argon2).
- Le transport fichier est un POC: un tiers qui lit le dossier lit les blobs
  (illisibles sans la cle privee, mais metadata visible). Passer au socket/onion.

## Legal
Tor, chiffrement et consultation de contenus legaux sont legaux en France/EU.
Ne jamais telecharger/executer de contenu illegal.
