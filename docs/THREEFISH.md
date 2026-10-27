# Choix Threefish-1024

## Utilisation

Au chiffrement, choisir **Threefish-1024** dans **Options des fichiers →
Algorithme de chiffrement**. XChaCha20 reste le choix initial. Le déchiffrement
lit la suite dans le volume ; aucun choix manuel d'algorithme n'est nécessaire.
Le choix peut être enregistré dans un profil personnel et exporté en JSON.

Threefish-1024 utilise la plus grande variante définie de Threefish : **bloc
et clé de 1024 bits, tweak de 128 bits, 80 tours complets**. Une taille de clé
plus grande n'est pas une preuve de sécurité supérieure à XChaCha20 : la
sécurité dépend aussi du mot de passe, de la dérivation, de l'authentification
et de l'implémentation. Le format Tasarut reste soumis à la revue indépendante
prévue dans la feuille de route.

Le chiffrement par blocs est fourni par **RustCrypto `threefish` 0.6**, le mode
compteur par **RustCrypto `ctr` 0.10**, et l'authentification par
**HMAC-SHA3-512**. Threefish n'est pas utilisé directement en ECB ni comme
fonction de hachage Skein dans cette construction.

## Construction fixe

- Préhash BLAKE2b-512 des composants mot de passe/fichiers-clés préfixés de
  leurs longueurs, avec le domaine `Tasarut/v5/threefish1024/password+keyfiles` ;
- **Argon2id v1.3 : 262144 Kio, 6 itérations, 4 voies, sortie de 192 octets** ;
- octets `[0..128]` : clé Threefish-1024 ;
- octets `[128..192]` : clé HMAC-SHA3-512 distincte ;
- sel de 32 octets, préfixe de compteur de 24 octets et tweak de 16 octets
  frais, issus du CSPRNG système pour chaque volume ;
- chiffrement en flux, mode **CTR128BE** sur des blocs de 128 octets ;
- authentification **encrypt-then-MAC**, tag de 64 octets.

Pour le bloc numéro `i`, l'entrée de Threefish est exactement :

```text
préfixe_aléatoire[24] || zéro[88] || u128_big_endian(i)
```

Le compteur débute à zéro. Le tweak reste fixe pendant le volume et est
indépendant du préfixe. Le mode `ctr` contrôle l'épuisement du compteur ; les
longueurs de fichier représentables en u64 restent très en dessous de sa
capacité. Aucune bourre de fin de bloc n'est ajoutée : la longueur chiffrée est
celle du flux fourni, éventuellement compressé.

Les fichiers-clés gardent leurs règles : contenu et ordre identiques à la
lecture, noms sans influence sur les clés.

## Formats et options

| Option | Comportement |
| --- | --- |
| Volume normal | Nouveau format **v5**, suite 1 |
| Compression | Zstandard avant Threefish |
| Reed–Solomon | Enveloppe v3 contenant le volume v5 |
| Découpage | Manifeste et parties existants, liés aux clés de la suite Threefish |
| Déniabilité | Volume intérieur v5 ; enveloppe extérieure XChaCha20/BLAKE2b inchangée |
| Volume révocable | **v4, suite 3**, chiffrement direct avec le secret TPM |
| Récupération forcée | Possible pour v5, explicitement non authentifiée ; interdite pour les volumes révocables et l'enveloppe opaque |
| Cascade paranoïaque | Choix distinct XChaCha20 → Serpent ; combinaison refusée avec Threefish |

Les restrictions existantes du mode révocable restent applicables : aucun
commentaire public, découpage, déniabilité ou déchiffrement forcé. Les limites
de récupération de parties endommagées restent celles du manifeste actuel,
même si le volume intérieur utilise Reed–Solomon.

L'authentification normale précède la décompression et la production du clair,
puis est revérifiée en seconde passe avant publication sans écrasement.
Les tampons et matières de clés gérés par Tasarut utilisent `Zeroizing` ; les
fonctions de zeroization de Threefish et CTR sont activées pour leurs états
persistants. Ces mesures ne garantissent pas l'effacement de toutes les copies
temporaires créées par les bibliothèques, le compilateur ou l'IPC.

## Compatibilité

Les formats v1/v2/v3/v4 existants et leurs vecteurs de référence sont conservés.
Les anciens lecteurs qui ne connaissent pas v5 ou la suite 3 de v4 refusent ces
nouveaux volumes. Les commentaires de v5 restent **publics et non authentifiés**,
comme ceux de v1/v2 ; les fichiers révocables n'en contiennent pas.

Le champ facultatif `algorithm` des profils et requêtes accepte uniquement
`xchacha20` et `threefish1024`. Son absence signifie `xchacha20` pour les anciens
profils. Les noms inconnus et la combinaison Threefish avec `paranoid: true`
sont refusés. Les profils exportés avec le nouveau champ nécessitent un client
qui le comprend.

## Vecteurs et vérifications

`scripts/generate-threefish-vectors.py` est indépendant du code Rust. Il
implémente la primitive à partir de la spécification Skein 1.3 avec des entiers
Python, vérifie deux KAT publiés (clé/tweak nuls et non nuls), puis utilise
libargon2 et Python `hashlib`/`hmac` pour générer les volumes complets.

```bash
python3 scripts/generate-threefish-vectors.py v5
python3 scripts/generate-threefish-vectors.py v4
```

Les résultats sont conservés dans `v5-threefish.hex` et `v4-threefish.hex`.
Les tests comparent les octets complets du chiffrement et déchiffrent ces
références, y compris plusieurs blocs CTR et des écritures non alignées.

Les contrôles couvrent les fichiers vides et les frontières de 128 octets,
les flux multi-tampons, les transports, les mauvais secrets, les modifications
d'en-tête/contenu/tag, les troncatures, l'annulation, les collisions et la
révocation d'un secret simulé. Les profils et l'interface sont vérifiés en trois
langues, avec détection automatique et sans secrets enregistrés dans les profils.

La variante TPM est vérifiée avec un fournisseur mémoire ; une qualification
sur TPM physique reste nécessaire selon [TPM-QUALIFICATION.md](TPM-QUALIFICATION.md).
