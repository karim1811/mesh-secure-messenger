# Mesh Secure Messenger - Wallet crypto non-custodial (etape 4)

Wallet EVM (ETH-compatible) leger et NON-CUSTODIAL : la cle privee reste
sur ta machine, chiffree par passphrase (scrypt + Fernet, meme schema que
client.py). Aucun relais de fonds, aucun node complet : c'est un SIGNER.

Usage (CLI):
```bash
python wallet.py new              # cree id_wallet.json (chiffre par passphrase)
python wallet.py address          # affiche l'adresse 0x...
python wallet.py sign "mon msg"   # signature EIP-191 (personal_sign)
python wallet.py verify <addr> <sig_hex> <msg>   # True/False
python wallet.py balance [rpc]    # solde via RPC public (optionnel, hors-ligne OK)
```

Integration messagerie:
- On peut signer un message E2E avec la cle blockchain pour prouver son
  identite (cle EVM = identite web3, decouplage du pseudo du chat).
- Le wallet est INDEPENDANT du transport (Tor / mesh / socket) : on signe
  le blob deja chiffre si besoin, ou un texte arbitraire.

SECURITE:
- Cle privee JAMAIS en clair sur disque (chiffree scrypt+Fernet).
- Non-custodial: personne d'autre n'y a acces. Si tu perds la passphrase,
  les fonds sont perdus (comme tout vrai wallet self-custody).
- Wallet de test uniquement pour l'instant : pas d'envoi de transaction
  on-chain dans cette etape (signer/verifier seulement).
