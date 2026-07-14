"""wallet.py - Wallet crypto NON-CUSTODIAL (etape 4).

Cote a cote de la messagerie E2E : permet de signer/verifier des messages
et de gerer une identite blockchain (ETH/EVM) directement depuis la messagerie,
sans tiers. Les cles privees restent LOCALES (non-custodial).

Primitives:
  - secp256k1 (meme courbe que Bitcoin/ETH) via eth_account / coincurve
  - adresse derivee de la cle publique (keccak256)
  - signature EIP-191 (personal_sign) et EIP-712-ready

NE FAIT PAS:
  - pas de relais de fonds, pas de node complet : c'est un signer leger.
  - pas de connexion reseau par defaut (RPC optionnel pour lire le solde).

Usage (CLI):
  python wallet.py new            -> cree id_wallet.json (chiffre par passphrase)
  python wallet.py address        -> affiche l'adresse
  python wallet.py sign "message" -> signature EIP-191
  python wallet.py verify addr sig "message" -> True/False
  python wallet.py balance [rpc_url] -> solde (RPC public par defaut)
"""
import sys, os, json, getpass
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak
import base64

BASE = os.path.dirname(os.path.abspath(__file__))
WALLET_FILE = os.path.join(BASE, "id_wallet.json")

# reutilise le meme schema de chiffrement que client.py (scrypt + Fernet)
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet
import base64 as _b64


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
    return _b64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def _store(priv_hex: str, passphrase: str):
    salt = os.urandom(16)
    key = _derive_key(passphrase, salt)
    token = Fernet(key).encrypt(priv_hex.encode("utf-8"))
    json.dump({"salt": salt.hex(), "v": 1, "data": token.decode("ascii")},
              open(WALLET_FILE, "w"))


def _load(passphrase: str) -> str:
    blob = json.load(open(WALLET_FILE))
    key = _derive_key(passphrase, bytes.fromhex(blob["salt"]))
    return Fernet(key).decrypt(blob["data"].encode("ascii")).decode("ascii")


def new_wallet(passphrase: str):
    acct = Account.create()
    _store(acct.key.hex(), passphrase)
    return acct.address


def address() -> str:
    pw = getpass.getpass("Passphrase wallet: ")
    priv = _load(pw)
    return Account.from_key(priv).address


def sign(message: str) -> str:
    pw = getpass.getpass("Passphrase wallet: ")
    priv = _load(pw)
    acct = Account.from_key(priv)
    signed = acct.sign_message(encode_defunct(text=message))
    return signed.signature.hex()


def verify(addr: str, sig_hex: str, message: str) -> bool:
    try:
        rec = Account._recover_hash(keccak(text=message) if False else None, None) \
            if False else Account.recover_message(encode_defunct(text=message),
                                                  signature=bytes.fromhex(sig_hex))
        return rec.lower() == addr.lower()
    except Exception:
        return False


def balance(rpc_url: str = "https://cloudflare-eth.com"):
    pw = getpass.getpass("Passphrase wallet: ")
    priv = _load(pw)
    addr = Account.from_key(priv).address
    try:
        from web3 import Web3
        w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 8}))
        wei = w3.eth.get_balance(addr)
        return w3.from_wei(wei, "ether")
    except Exception as e:
        return f"(RPC indisponible: {e})"


def main():
    if len(sys.argv) < 2:
        print(__doc__.split("Usage")[0])
        print("Usage: python wallet.py {new|address|sign|verify|balance}")
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "new":
        pw = getpass.getpass("Passphrase pour chiffrer le wallet: ")
        addr = new_wallet(pw)
        print(f"[+] Wallet cree. Adresse: {addr}")
        print("    Cle privee chiffree dans id_wallet.json (non-custodial).")
    elif cmd == "address":
        print(address())
    elif cmd == "sign":
        msg = sys.argv[2] if len(sys.argv) > 2 else ""
        print(sign(msg))
    elif cmd == "verify":
        if len(sys.argv) < 5:
            print("Usage: python wallet.py verify <addr> <sig_hex> <message>")
            sys.exit(1)
        ok = verify(sys.argv[2], sys.argv[3], sys.argv[4])
        print("VERIFY:", ok)
    elif cmd == "balance":
        rpc = sys.argv[2] if len(sys.argv) > 2 else "https://cloudflare-eth.com"
        print(f"Solde: {balance(rpc)} ETH")
    else:
        print("Commande inconnue:", cmd)


if __name__ == "__main__":
    main()
