import argparse
import os
import base64
from pathlib import Path
from nacl.secret import SecretBox
from nacl.utils import random
from nacl.exceptions import CryptoError


def get_box() -> SecretBox:
    """
    Récupère la clé depuis la variable d'environnement SECRETBOX_KEY.
    La clé doit être encodée en base64.
    """
    key_b64 = os.environ.get("SECRETBOX_KEY")

    if not key_b64:
        raise SystemExit(
            "❌ SECRETBOX_KEY non défini.\n"
            "Ajoute-le dans Codespaces secrets ou export local.\n"
        )

    try:
        key = base64.b64decode(key_b64)
    except Exception:
        raise SystemExit("❌ Clé invalide (doit être en base64).")

    if len(key) != SecretBox.KEY_SIZE:
        raise SystemExit("❌ La clé doit faire 32 bytes.")

    return SecretBox(key)


def encrypt_file(input_path: Path, output_path: Path) -> None:
    box = get_box()
    data = input_path.read_bytes()

    nonce = random(SecretBox.NONCE_SIZE)
    encrypted = box.encrypt(data, nonce)

    output_path.write_bytes(encrypted)


def decrypt_file(input_path: Path, output_path: Path) -> None:
    box = get_box()
    encrypted = input_path.read_bytes()

    try:
        decrypted = box.decrypt(encrypted)
    except CryptoError:
        raise SystemExit("❌ Échec du déchiffrement (clé incorrecte ou fichier altéré).")

    output_path.write_bytes(decrypted)


def main():
    parser = argparse.ArgumentParser(
        description="Chiffrement/Déchiffrement avec PyNaCl SecretBox."
    )
    parser.add_argument("mode", choices=["encrypt", "decrypt"])
    parser.add_argument("input")
    parser.add_argument("output")

    args = parser.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)

    if not in_path.exists():
        raise SystemExit(f"❌ Fichier introuvable: {in_path}")

    if args.mode == "encrypt":
        encrypt_file(in_path, out_path)
        print(f"✅ Chiffré: {in_path} -> {out_path}")
    else:
        decrypt_file(in_path, out_path)
        print(f"✅ Déchiffré: {in_path} -> {out_path}")


if __name__ == "__main__":
    main()