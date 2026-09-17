# TP Cybersécurité : Opération Hashbreaker - Cassage de mots de passe hachés

## Phase 1 — Comprendre le hachage

Un hash est une empreinte numérique à sens unique. Deux propriétés fondamentales :
*   **Irréversibilité :** Impossible de retrouver le mot de passe depuis le hash.
*   **Effet d'avalanche :** Un seul caractère différent change totalement le résultat.

**Générer ses premiers hashs**
```bash
# Hash MD5 du mot 'bonjour'
echo -n "bonjour" | md5sum

# Hash SHA-256
echo -n "bonjour" | sha256sum

# Comparer avec 'Bonjour' (une seule majuscule)
echo -n "Bonjour" | sha256sum

# Hacher votre propre prénom
echo -n "votre_prenom" | sha256sum

Question 1 : Les hash de « bonjour » et « Bonjour » sont-ils proches ou totalement différents ? Expliquez.
Les deux hashs sont totalement différents, il n’y a aucune correspondance distincte. C'est l'effet d'avalanche.
Question 2 : Si deux utilisateurs ont le même mot de passe, leurs hash sont-ils identiques ?
Oui, par défaut les hashs des deux mots de passe seront identiques. Le salt (caractères aléatoires) peut être ajouté au mot de passe avant le hash pour que 2 mots de passe identiques aient un hash différent.
Le format /etc/shadow
Sur Linux, les mots de passe hachés sont stockés dans le fichier /etc/shadow. Format d'une ligne :
# Format : login:$algo$sel$hash:dernierChgt:...
alice:$6$rounds=5000$sel123abc$HASH_SHA512...:19000:0:99999:7:::
#      ^             ^         ^
#   $6=SHA-512      sel       hash

# $1 = MD5 (obsolète, très vulnérable)
# $5 = SHA-256
# $6 = SHA-512 (standard actuel sur Linux)

# Afficher les premières lignes (en root) :
sudo cat /etc/shadow | head -5

Attention : $1 (MD5) est encore présent sur de vieux systèmes et est extrêmement vulnérable. $6 (SHA-512) est le standard actuel sur les distributions Linux modernes.
Question 3 : Quel algorithme est utilisé sur votre VM Kali ? Comment l'identifiez-vous ?
L’algorithme utilisé est le SHA-512 car c’est le standard actuel sous Linux. On peut connaître l’algorithme utilisé par le caractère entre les deux « $ » dans la structure du fichier shadow (ex: $6$ pour SHA-512). Ici, il s'agissait d'un « y », une variante moderne.
Phase 2 — Identifier et préparer les cibles
Identifier un hash inconnu
L'utilisation de l'outil hashid permet d'identifier l'algorithme utilisé lors d'une fuite de données :
# Installer hashid si nécessaire
pip install hashid

# Tester sur les hash suivants :
hashid 5f4dcc3b5aa765d61d8327deb882cf99
# Résultat : MD5

hashid 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
# Résultat : SHA-1

hashid '$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'
# Résultat : Bcrypt

Information : Le hash MD5 5f4dcc3b... correspond au mot de passe « password ». C'est l'un des hash les plus reconnus dans les bases de données piratées.
Créer le fichier de hash cibles
On simule une fuite de base de données. Créez ce fichier sur votre VM Kali :
cat > ~/hashes_cibles.txt << 'EOF'
alice:5f4dcc3b5aa765d61d8327deb882cf99
bob:e10adc3949ba59abbe56e057f20f883e
charlie:827ccb0eea8a706c4c34a16891f84e7b
diana:25f9e794323b453885f5181f1b624d0b
eric:d8578edf8458ce06fbc5bb76a58c5ca4
EOF

# Extraire uniquement les hash (sans les noms)
cut -d: -f2 ~/hashes_cibles.txt > ~/hash_only.txt
cat ~/hash_only.txt

Question 4 : Quelle différence entre une attaque par dictionnaire et une attaque brute-force ?
Une attaque par dictionnaire utilise des fichiers texte avec des mots de passe probables ou ayant déjà fuité. L'attaque par force pure (brute-force) va tenter toutes les combinaisons de caractères possibles. L'attaque par dictionnaire est donc beaucoup plus ciblée et rapide.
Question 5 : À 1 milliard de hash MD5/s, combien de temps pour tester tous les MDP de 6 lettres minuscules ?
Il y a 26 lettres minuscules possibles pour 6 emplacements, soit 26^6 = 308 915 776 mots de passe possibles.
En divisant par 1 milliard de calculs par seconde : 308 915 776 / 1 000 000 000 = ~0,31 seconde. Il faut donc moins d'une demi-seconde.
Phase 3 — Attaque par dictionnaire
Attaque avec John the Ripper
John the Ripper est l'outil de référence. Il teste automatiquement des millions de mots depuis rockyou.txt (14 millions de mots de passe issus de vraies fuites).
# Vérifier la version installée (Kali : inclus par défaut)
john --version

# Décompresser rockyou.txt si nécessaire
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# Lancer l'attaque par dictionnaire sur vos hash MD5
john --format=raw-md5 \
--wordlist=/usr/share/wordlists/rockyou.txt \
~/hash_only.txt

# Dans un 2e terminal : voir l'avancement en temps réel
watch -n 2 john --show --format=raw-md5 ~/hash_only.txt

Point clé : Les 5 hash tombent en moins de 30 secondes avec rockyou.txt (password, 123456, 12345, 123456789, qwerty). Ces mots de passe classiques ne résistent pas une seconde.
Attaque avec règles de mutation
Les utilisateurs pensent sécuriser leurs mots de passe avec des substitutions (a→@, e→3, majuscules). John les teste automatiquement.
# Générer le hash MD5 de 'P@ssw0rd!'
echo -n "P@ssw0rd!" | md5sum

# → copier le hash obtenu dans la commande suivante :
echo 'VOTRE_HASH_ICI' > ~/hash_sophistique.txt

# Attaque avec règles de mutation best64
john --format=raw-md5 \
--wordlist=/usr/share/wordlists/rockyou.txt \
--rules=best64 \
~/hash_sophistique.txt

john --show --format=raw-md5 ~/hash_sophistique.txt

Attention : Les substitutions « leetspeak » sont parfaitement connues des attaquants et n'apportent aucune sécurité face à des règles de mutation.
Question 6 : Pourquoi « P@ssw0rd! » est-il cassé presque aussi vite que « password » ?
Car le mot de passe de base est contenu dans le dictionnaire rockyou. L’outil John teste d’office les substitutions classiques (leetspeak).
Question 7 : Quel type de mot de passe résisterait vraiment à cette attaque ?
Un mot de passe long (minimum 10/12 caractères) contenant majuscules, minuscules, chiffres et caractères spéciaux, non basé sur un mot du dictionnaire, et protégé côté serveur par un sel (salt).
Bonus : Rainbow Tables en ligne
Avant les outils modernes, les attaquants précalculaient des tables (hash → mot de passe).
# Hash MD5 de 'azerty'
echo -n "azerty" | md5sum
# → ab4f63f9ac65152575886860dde480d1

# Tester sur CrackStation (15 milliards de hash précalculés) :
# [https://crackstation.net/](https://crackstation.net/)
# → Résultat en moins d'une seconde

Question 8 : Pourquoi les rainbow tables deviennent-elles inutiles si un sel est ajouté ?
Car il faudrait avoir une table précalculée contenant un mot de passe associé à un sel généré aléatoirement. Le sel changeant pour chaque utilisateur, il est impossible de précalculer toutes les combinaisons.
Phase 4 — Contre-mesures et bonnes pratiques
Le salage
Le sel est une valeur aléatoire unique générée pour chaque utilisateur et concaténée au mot de passe avant le hachage.
import hashlib, os
mdp = 'password'

# Sans sel : toujours le même hash
h_sans = hashlib.md5(mdp.encode()).hexdigest()

# Avec sel aléatoire unique
sel1 = os.urandom(16).hex()
sel2 = os.urandom(16).hex()
h1 = hashlib.sha256((sel1 + mdp).encode()).hexdigest()
h2 = hashlib.sha256((sel2 + mdp).encode()).hexdigest()

print(f'Sans sel : {h_sans}')
print(f'Avec sel1 : {h1}')
print(f'Avec sel2 : {h2}')
print(f'Même MDP, hash différents : {h1 != h2}')

Question 9 : Le sel est stocké en clair à côté du hash dans /etc/shadow. Pourquoi est-ce acceptable ?
Car sa fonction n’est pas de rester secrète. Il protège contre les Rainbow Tables et assure que deux mots de passe identiques aient un hash différent. Un attaquant devra forcer chaque utilisateur un par un (brute-force).
Bcrypt : la lenteur comme protection
MD5 et SHA-256 sont conçus pour être rapides (vulnérables). bcrypt est intentionnellement lent.
pip install bcrypt

import hashlib, bcrypt, time
mdp = b'monmotdepasse'

# Vitesse MD5
t = time.time()
for _ in range(100000):
    hashlib.md5(mdp).hexdigest()
print(f'MD5 : 100 000 hash en {time.time()-t:.3f}s')

# Vitesse bcrypt (intentionnellement lent)
t = time.time()
for _ in range(3):
    bcrypt.hashpw(mdp, bcrypt.gensalt(rounds=12))
print(f'bcrypt : 3 hash en {time.time()-t:.2f}s')

Conclusion des mesures de robustesse :
 * MD5 / SHA-256 : Résistance très basse (plusieurs millions de hashs/s).
 * Bcrypt (cost=12) : Très bonne résistance (~4 hashs/s).
 * Algorithmes recommandés : bcrypt, Argon2id, scrypt.

