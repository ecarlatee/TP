# TP Cybersécurité : Opération Hashbreaker - Cassage de mots de passe hachés

# Phase 1 — Comprendre le hachage

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
```bash
Question 1 : Les hash de « bonjour » et « Bonjour » sont-ils proches ou totalement différents ? Expliquez.
Les deux hashs sont totalement différents, il n’y a aucune correspondance distincte entre les deux chaînes de caractères. C'est l'effet d'avalanche.
Question 2 : Si deux utilisateurs ont le même mot de passe, leurs hash sont-ils identiques ?
Oui, par défaut les hashs des deux mots de passe seront identiques. Le salt (caractères aléatoires) peut être ajouté au mot de passe avant le hash pour que 2 mots de passe identiques aient un hash différent.
Le format /etc/shadow
Sur Linux, les mots de passe hachés sont stockés dans le fichier /etc/shadow.
Question 3 : Quel algorithme est utilisé sur votre VM Kali ? Comment l'identifiez-vous ?
L’algorithme utilisé est le SHA-512 car c’est le standard actuel sous Linux. On peut connaître l’algorithme utilisé par le caractère entre les deux « $ » dans la structure du fichier shadow (ex: $6$ pour SHA-512). Ici, il s'agissait d'un « y », une variante moderne.
# Phase 2 — Identifier et préparer les cibles
Identifier un hash inconnu
L'utilisation de l'outil hashid permet d'identifier l'algorithme utilisé lors d'une fuite de données :
hashid 5f4dcc3b5aa765d61d8327deb882cf99
# Résultat : MD5

hashid 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
# Résultat : SHA-1

hashid '$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'
# Résultat : Bcrypt

Question 4 : Quelle différence entre une attaque par dictionnaire et une attaque par force brute ?
Une attaque par dictionnaire utilise des fichiers texte avec des mots de passe probables ou ayant déjà fuité. L'attaque par force pure (brute-force) va tenter toutes les combinaisons de caractères possibles. L'attaque par dictionnaire est donc beaucoup plus ciblée et rapide.
Question 5 : À 1 milliard de hashs MD5/s, combien de temps pour tester tous les mots de passe de 6 lettres minuscules ?
Il y a 26 lettres minuscules possibles pour 6 emplacements, soit 26^6 = 308 915 776 mots de passe possibles.
Si on divise par 1 milliard de calculs par seconde : 308 915 776 / 1 000 000 000 = ~0,31 seconde. Il faut donc moins d'une demi-seconde.
# Phase 3 — Attaques par dictionnaire (John The Ripper)
En utilisant l'outil John the Ripper et le dictionnaire rockyou.txt (contenant 14 millions de mots de passe fuités), les mots de passe classiques (ex: password, 123456, qwerty) sont cassés en une fraction de seconde.
Question 6 : Lors d'une attaque avec règles de mutation, pourquoi un mot de passe comme « P@ssw0rd! » est-il cassé presque aussi vite que « password » ?
Car le mot de passe de base est contenu dans le dictionnaire rockyou. L’outil John teste d’office les substitutions classiques (leetspeak : a->@, o->0). Ces substitutions n'apportent aucune sécurité réelle face à un outil de cassage configuré avec des règles de mutation.
Question 7 : Quel type de mot de passe résisterait vraiment à cette attaque ?
Un mot de passe long (minimum 10/12 caractères) contenant majuscules, minuscules, chiffres et caractères spéciaux, non basé sur un mot du dictionnaire, et protégé côté serveur par un sel (salt).
Question 8 : Pourquoi les "Rainbow Tables" (tables de hashs précalculés) deviennent-elles inutiles si un sel est ajouté ?
Car il faudrait avoir une table précalculée contenant un mot de passe associé à un sel généré aléatoirement. Puisque le sel change pour chaque utilisateur, il est techniquement impossible et beaucoup trop lourd de précalculer toutes les combinaisons possibles.
Phase 4 — Contre-mesures et bonnes pratiques
Le salage
Le sel (salt) est une valeur aléatoire unique générée pour chaque utilisateur et concaténée au mot de passe avant le hachage.
Script Python de démonstration du salage :
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
Car sa fonction n’est pas de rester secrète. Il protège contre les Rainbow Tables et assure que deux mots de passe identiques aient un hash différent. Même avec la connaissance du sel, un attaquant va devoir faire du brute force complet sur chaque utilisateur un par un.
Bcrypt : la lenteur comme protection
MD5 et SHA-256 sont conçus pour être rapides (plus d'un million de hashs calculés par seconde), ce qui est un problème pour le stockage de mots de passe. bcrypt est intentionnellement lent.
Script Python comparatif de vitesse (MD5 vs Bcrypt) :
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
 * MD5 / SHA-256 : Résistance très basse (plusieurs millions de hashs/s). Une attaque GPU pour un mot de passe de 8 caractères prendrait quelques heures.
 * Bcrypt (cost=12) : Très bonne résistance (~4 hashs/s). Une attaque pour un mot de passe de 8 caractères prendrait des milliers d'années.
 * Algorithmes recommandés : bcrypt, Argon2id, scrypt.

