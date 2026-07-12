"""
crypto_utils.py - Couche CHIFFREMENT (E2E) de la messagerie.
Independant du transport (internet / mesh / onion).

Primitives:
  - X25519 : echange de cles (asymetrique, courbe elliptique)
  - AES-256-GCM : chiffrement symmetrique des messages + integrite
  - Ed25519 : signature (option, prouve l'expediteur)

Aucune donne en clair ne sort de ce module vers le transport.
"""
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
import os, base64, json


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


# ---------------------------------------------------------------------------
# 1. PAIRE DE CLES D'IDENTITE (persiste sur disque, NEVER partage la privee)
# ---------------------------------------------------------------------------
def generate_identity(name: str):
    """Cree une paire X25519 (chiffrement) + Ed25519 (signature)."""
    enc_priv = X25519PrivateKey.generate()
    sig_priv = Ed25519PrivateKey.generate()
    return {
        "name": name,
        "enc_priv": enc_priv,
        "enc_pub": enc_priv.public_key(),
        "sig_priv": sig_priv,
        "sig_pub": sig_priv.public_key(),
    }


def pubkey_bundle(identity) -> dict:
    """Le seul truc qu'on envoie en clair a son correspondant."""
    return {
        "name": identity["name"],
        "enc_pub": _b64(identity["enc_pub"].public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
        "sig_pub": _b64(identity["sig_pub"].public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
    }


def load_remote_pubkeys(bundle: dict) -> dict:
    return {
        "name": bundle["name"],
        "enc_pub": X25519PublicKey.from_public_bytes(_unb64(bundle["enc_pub"])),
        "sig_pub": Ed25519PublicKey.from_public_bytes(_unb64(bundle["sig_pub"])),
    }


# ---------------------------------------------------------------------------
# 2. SESSION E2E (un "blob" chiffre par message, forward-secret simplifie)
# ---------------------------------------------------------------------------
def derive_session_key(my_enc_priv: X25519PrivateKey, their_enc_pub: X25519PublicKey) -> bytes:
    """ECDH: meme secret des deux cotes -> clé AES 256 bits."""
    shared = my_enc_priv.exchange(their_enc_pub)
    # HKDF etire le secret en 32 octets utilisables comme clé AES
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"mesh-secure-v1").derive(shared)


def encrypt_message(session_key: bytes, plaintext: str, sig_priv: Ed25519PrivateKey) -> str:
    """Chiffre + signe. Renvoie un blob base64 (illisible) pret pour le transport."""
    nonce = os.urandom(12)                     # jamais reutilise avec la meme clé
    aes = AESGCM(session_key)
    ct = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
    # signature du ciphertext (prouve que c'est bien nous, pas un MITM)
    sig = sig_priv.sign(nonce + ct)
    payload = {"n": _b64(nonce), "c": _b64(ct), "s": _b64(sig)}
    return _b64(json.dumps(payload).encode("utf-8"))


def decrypt_message(session_key: bytes, blob: str, sig_pub: Ed25519PublicKey) -> str:
    """Verifie la signature puis dechiffre. Renvoie le clair OU leve une erreur."""
    payload = json.loads(_unb64(blob))
    nonce = _unb64(payload["n"])
    ct = _unb64(payload["c"])
    sig = _unb64(payload["s"])
    sig_pub.verify(sig, nonce + ct)            # abort si faux expediteur
    aes = AESGCM(session_key)
    pt = aes.decrypt(nonce, ct, None)
    return pt.decode("utf-8")
