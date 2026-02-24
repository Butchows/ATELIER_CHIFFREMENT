# Atelier – Chiffrement/Déchiffrement (Python `cryptography`) dans GitHub Codespaces

## 1) Lancer le projet dans Codespaces
- Fork / clone ce repo
- Bouton **Code** → **Create codespace on main**

## 2) Installer la bibliothèque Python Cryptographie
```bash
pip install -r requirements.txt
```
## 3) Partie A – Chiffrer/Déchiffrer un texte
```
python app/fernet_demo.py
```
**Quel est le rôle de la clé Fernet ?**  
La clé Fernet est une clé symétrique secrète de 256 bits encodée en Base64, utilisée pour chiffrer et authentifier les données avec AES et HMAC issue de la bibliothèque python cryptography. Un token Fernet (c'est à dire le résultat chiffré) contient :  
```
| Version | Timestamp | IV | Ciphertext | HMAC |
```
* Version (1 octet) : Valeur actuelle : 0x80
* Timestamp (8 octets) : Permet l'expiration des tokens
* IV (16 octets) : Généré aléatoirement - Garantit que deux messages identiques produisent des ciphertexts différents
* Ciphertext (variable) : Résultat du chiffrement AES-128-CBC qui contient les données
* HMAC (32 octets) : Protège contre toute modification
  
## 4) Partie B – Chiffrer/Déchiffrer un fichier
Créer un fichier de test :  
```
echo "Message Top secret !" > secret.txt
```
Chiffrer :
```
python app/file_crypto.py encrypt secret.txt secret.enc
```
Déchiffrer :
```
python app/file_crypto.py decrypt secret.enc secret.dec.txt
cat secret.dec.txt
```
**Que se passe-t-il si on modifie un octet du fichier chiffré ?**  
Le message sera totalement changé car un token change tout pour le déchiffrement
 
**Pourquoi ne faut-il pas commiter la clé dans Git ?**   
Si la clé est commit dans Git, alors le message sera déchiffrable, il n'y aura donc plus aucun intérêt à ce qu'il soit crypté

## 5) Atelier 1 :
Dans cet atelier, la clé Fernet n'est plus générée dans le code mais stockée dans un Repository Secret Github. Ecrivez un nouveau programme **python app/fernet_atelier1.py** qui utilisera une clé Fernet caché dans un Secret GitHub pour encoder et décoder vos fichiers.

## 6) Atelier 2 :
Les bibliothèques qui proposent un système complet, sûr par défaut et simple d’usage comme Fernet de la bibliothèse Cryptographie sont relativement rares. Toutefois, la bibliothèque PyNaCl via l'outil SecretBox est une très bonne alternative. **travail demandé :** Construire une solution de chiffrement/déchiffrement basé sur l'outils SecretBox de la bibliothèque PyNaCl.









