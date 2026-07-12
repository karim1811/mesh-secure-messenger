"""
client.py - Messagerie chiffree E2E (etape 1).
Transport minimal: fichiers sur disque (inbox). Echange de cles via fichiers.
Remplacable plus tard par socket / .onion / Meshtastic SANS toucher au chiffrement.

Usage:
  python client.py alice            # demarre l'utilisateur "alice"
  python client.py bob              # dans une autre fenetre, l'utilisateur "bob"

Au 1er lancement: genere son identite, ecrit sa cle publique dans pub_alice.json
Pour discuter: chaque user doit avoir le pub de l'autre (on copie/colle ou on lit le fichier).
"""
import sys, os, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crypto_utils import (generate_identity, pubkey_bundle, load_remote_pubkeys,
                          derive_session_key, encrypt_message, decrypt_message)

BASE = os.path.dirname(os.path.abspath(__file__))


def path(*a): return os.path.join(BASE, *a)


def main():
    if len(sys.argv) < 2:
        print("Usage: python client.py <nom>")
        sys.exit(1)
    me = sys.argv[1]
    idfile = path(f"id_{me}.json")

    # --- identite (generee une fois, cles privees jamais partagees) ---
    if not os.path.exists(idfile):
        print(f"[*] Generation de l'identite pour {me}...")
        # on stocke les cles privees en brut pour le POC local (NE PAS faire en prod)
        import_temp_store(me)
    ident = load_identity(me)

    # --- publication de la cle publique ---
    pub = pubkey_bundle(ident)
    with open(path(f"pub_{me}.json"), "w") as f:
        json.dump(pub, f, indent=2)
    print(f"[+] Cle publique ecrite dans pub_{me}.json (donne-la a ton correspondant)")

    # --- recuperation de la cle publique du correspondant ---
    others = [n for n in ("alice", "bob", "carol") if n != me and os.path.exists(path(f"pub_{n}.json"))]
    if not others:
        print("[!] En attente de la cle publique du correspondant (pub_<nom>.json)...")
        print("    Pose le fichier, puis relance le client.")
        return
    other = others[0]
    with open(path(f"pub_{other}.json")) as f:
        remote = load_remote_pubkeys(json.load(f))
    print(f"[+] Correspondant detecte: {remote['name']}")

    # --- session E2E (meme clé des deux cotes via ECDH) ---
    my_session = derive_session_key(ident["enc_priv"], remote["enc_pub"])
    # note: le correspondant calcule la meme clé avec sa privee + notre publique

    inbox = path(f"inbox_{me}.json")
    if not os.path.exists(inbox):
        json.dump([], open(inbox, "w"))

    print(f"\n=== Session E2E active ({me} <-> {other}) ===")
    print("Tape un message + Entree pour envoyer. 'quit' pour quitter.\n")

    seen = 0
    while True:
        # verifier la reception (transport = fichier, POC)
        msgs = json.load(open(inbox))
        if len(msgs) > seen:
            for blob in msgs[seen:]:
                try:
                    txt = decrypt_message(my_session, blob, remote["sig_pub"])
                    print(f"\n[{other}] {txt}")
                except Exception as e:
                    print(f"\n[!] message illisible / mauvais expediteur: {e}")
                seen += 1
            json.dump(msgs[:seen], open(inbox, "w"))

        line = input(f"[{me}] ").strip()
        if line.lower() == "quit":
            break
        if not line:
            continue
        blob = encrypt_message(my_session, line, ident["sig_priv"])
        # "envoi" = on pose le blob dans la inbox du correspondant
        out = path(f"inbox_{other}.json")
        data = json.load(open(out)) if os.path.exists(out) else []
        data.append(blob)
        json.dump(data, open(out, "w"))
        print("    (message chiffre envoye)")


# --- stockage POC des cles privees (fichier local, clair -> remplacer par passphrase) ---
def import_temp_store(me):
    ident = generate_identity(me)
    # serialisation brute pour le POC (a chiffrer avec un mot de passe en prod)
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    raw = {
        "enc_priv": ident["enc_priv"].private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw).hex(),
        "sig_priv": ident["sig_priv"].private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw).hex(),
    }
    json.dump(raw, open(path(f"id_{me}.json"), "w"))


def load_identity(me):
    raw = json.load(open(path(f"id_{me}.json")))
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    enc_priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(raw["enc_priv"]))
    sig_priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(raw["sig_priv"]))
    return {
        "name": me,
        "enc_priv": enc_priv,
        "enc_pub": enc_priv.public_key(),
        "sig_priv": sig_priv,
        "sig_pub": sig_priv.public_key(),
    }


if __name__ == "__main__":
    main()
