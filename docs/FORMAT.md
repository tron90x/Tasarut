# Tasarut : volumes v1/v2/v3/v4/v5, ensembles de parties et enveloppe opaque

Les formats sont spécifiques à Tasarut, incompatibles avec Picocrypt. XChaCha20 standard conserve le format v1 ; le mode paranoïaque utilise v2, suite 1. Threefish-1024 utilise v5, suite 1. Le format révocable v4 exige un secret matériel. Reed–Solomon utilise une enveloppe v3 contenant un volume v1, v2, v4 ou v5. Le lecteur détecte la suite et rejette les versions, suites ou flags inconnus.

## Volume Threefish-1024 v5 — suite 1

| Offset | Taille | Champ |
| --- | --- | --- |
| 0 | 8 | `TASARUT` suivi de `0x05` |
| 8 | 1 | Suite 1 : Threefish-1024-CTR128BE et HMAC-SHA3-512 ; autres valeurs refusées |
| 9 | 1 | Compression Zstandard : 0 ou 1 ; autres valeurs refusées |
| 10 | 32 | Sel Argon2id aléatoire |
| 42 | 24 | Préfixe aléatoire de compteur |
| 66 | 16 | Tweak Threefish aléatoire indépendant |
| 82 | 8 | Taille originale, u64 little-endian |
| 90 | 4 | Longueur du commentaire public, u32 little-endian, maximum 65536 |
| 94 | variable | Commentaire public UTF-8 |
| après commentaire | variable | Contenu chiffré, éventuellement précompressé |
| fin − 64 | 64 | HMAC-SHA3-512 |

La taille minimale est **158 octets**. Préhasher les composants mot de passe et
fichiers-clés comme v1 avec le domaine
`Tasarut/v5/threefish1024/password+keyfiles`, sans octet nul final. Utiliser
Argon2id v1.3 **262144 Kio / 6 itérations / 4 voies / 192 octets de sortie** :
clé Threefish de 128 octets puis clé HMAC distincte de 64 octets.

La primitive est Threefish-1024 à **80 tours complets**. Pour le bloc `i`,
chiffrer `préfixe[24] || zéro[88] || u128_big_endian(i)` avec le tweak de
l'en-tête, puis XORer le résultat avec les octets du flux. Le compteur débute
à zéro, sans padding de contenu ni réinitialisation entre les tampons.
Les mots u64 internes de Threefish suivent la spécification little-endian.

Le tag est `HMAC-SHA3-512(K_mac, en-tête[0..90] || ciphertext)`. La longueur du
commentaire et le commentaire restent publics et **non authentifiés**. Les
paramètres KDF sont fixes, jamais choisis par le fichier. Le lecteur authentifie
avant la production du clair et revérifie en seconde passe avant publication.
Voir [THREEFISH.md](THREEFISH.md) pour les options, vecteurs et limites.

## Volume révocable v4 — TPM2 NV

v4 est un format de chiffrement autonome en flux, et non une enveloppe contenant un volume déchiffrable par le seul mot de passe. Sa lecture requiert un enregistrement matériel indépendant. Le fichier peut être copié, mais il reste lié à cet enregistrement et au TPM qui le contient.

### En-tête public authentifié

| Offset | Taille | Champ |
| --- | --- | --- |
| 0 | 8 | `TASARUT` suivi de `0x04` |
| 8 | 1 | Suite : 1 standard, 2 paranoïaque, 3 Threefish-1024 |
| 9 | 1 | Compression Zstandard : 0 ou 1 ; autres valeurs refusées |
| 10 | 32 | Identifiant aléatoire du volume |
| 42 | 4 | Index TPM NV, u32 little-endian, dans `0x015a0000–0x015affff` |
| 46 | 32 | Sel Argon2id indépendant |
| 78 | 24 | Nonce XChaCha20, ou préfixe CTR Threefish pour la suite 3 |
| 102 | 16 | IV Serpent pour la suite 2 ; tweak Threefish indépendant pour la suite 3 ; inutilisé en standard mais toujours authentifié |
| 118 | 8 | Taille originale, u64 little-endian |
| 126 | variable | Contenu chiffré, éventuellement précompressé |
| fin − 64 | 64 | MAC de la suite |

Le nom original reste extérieur au format. Le commentaire public et les paramètres KDF variables sont absents. La taille minimale est 190 octets. Sans compression, la longueur du contenu chiffré doit être exactement la taille originale.

### Autorisation TPM et clés de contenu

Préhasher les mêmes composants préfixés par leurs longueurs que v1, mais avec le domaine **`Tasarut/v4/TPM-auth/password+keyfiles`**, sans octet nul final. Appliquer Argon2id v1.3 avec le sel public, **262144 Kio / 6 itérations / 4 voies / 64 octets de sortie**. Soit `A` cette sortie. L’autorisation de l’index est `A[0..32]`.

À la création, produire un secret frais `S` de 32 octets avec le CSPRNG système. L’enregistrement NV contient `identifiant[32] || S[32]`. Avant utilisation ou suppression, le fournisseur vérifie le namespace, SHA-256, la taille de 64 octets, l’absence de politique étrangère et les attributs exacts `AUTHREAD | AUTHWRITE | WRITEDEFINE | NO_DA | WRITTEN | WRITELOCKED` (`0x22042804`). Il exige que l’identifiant lu corresponde au fichier.

Pour chaque compteur `c`, calculer BLAKE2b-512 sans clé sur :

```text
"Tasarut/v4/payload-keys\0" || u8(suite) || u8(c) ||
A[64] || S[32] || identifiant[32] || u32(index NV)
```

Les tailles de ces composants sont fixes ; l’index est little-endian. La suite standard utilise le digest pour `c=0`, séparé en 32 octets XChaCha20 et 32 octets BLAKE2b-MAC. La suite paranoïaque concatène les digests pour `c=0` et `c=1` : 32 octets XChaCha20, 32 octets Serpent-256-CTR128BE, 64 octets HMAC-SHA3-512. Les domaines séparent l’autorisation des constructions v1/v2 et la dérivation de contenu v4. La possession du mot de passe et du fichier entier ne permet pas de recalculer `S`.

La suite 3 concatène les digests pour `c=0,1,2` : les 128 premiers octets sont
la clé Threefish-1024 et les 64 derniers la clé HMAC-SHA3-512. Les champs nonce
et tweak et le compteur suivent v5. L'autorisation `A` reste la même dérivation
fixe de 64 octets ; les anciens enregistrements v4 ne changent pas.

### Authentification et lecture

Les algorithmes et compteurs des suites sont ceux de v1/v2/v5. Calculer le MAC sur `en-tête[0..126] || ciphertext`. Tous les octets de l’en-tête sont authentifiés. La compression est un flux Zstandard niveau 3.

Au déchiffrement, vérifier la structure bornée, dériver `A`, obtenir et contrôler l’enregistrement matériel, puis authentifier le contenu entier. Revenir au début sur le même descripteur, recontrôler l’en-tête, déchiffrer et revérifier le MAC, le tag, la taille et la fin de fichier avant publication sans écrasement. La décompression est bornée par la taille authentifiée. La progression et l’annulation suivent les étapes usuelles.

Reed–Solomon peut envelopper **v4** avec le descripteur v3 et les mêmes blocs RS(136,128) ; la correction intervient avant les deux passes d’authentification. Le découpage, l’enveloppe opaque, les commentaires publics et la récupération forcée sont refusés pour v4 dans cette version.

### Publication et révocation

La création ne définit aucun index si les options ou la destination sont invalides. Après allocation du secret, chaque erreur ou annulation avant publication tente de supprimer l’index avec un jeton de nettoyage non annulé. Un échec de nettoyage est rapporté avec l’index, sans annoncer une sortie publiée. La publication du fichier est le point final ; une demande tardive ne transforme pas un résultat complet en échec.

La révocation exige une nouvelle authentification complète du volume et des contrôles d’identité dans le client natif. Le fournisseur relit l’identifiant sous autorisation, détruit uniquement cet index puis confirme son absence par `NV_ReadPublic`. Le MAC invalide, un index étranger, un accès refusé, une erreur de commande ou une absence non vérifiable ne justifient pas un résultat « révoqué ». Un retrait engagé peut achever malgré une annulation ; son résultat réel est rendu.

Le protocole natif utilise `tpm2-tools` sur un TCTI fixé au périphérique local, des memfds pour les autorisations/enregistrements, aucune clé sur disque et aucune alternative de coffre logiciel. Les volumes restent dépendants d’un TPM physique dont l’état ne peut être restauré. Une capture antérieure de clés, de texte clair ou d’état d’un TPM virtuel reste hors de cette propriété. Le swap persistant bloque l’utilisation ; les core dumps sont désactivés. Un redémarrage doit conserver le verrou `WRITEDEFINE` et le secret NV, tandis qu’une suppression ou perte du TPM rend le secret indisponible.

Le vecteur `v4-revocable.hex` est produit indépendamment par `scripts/generate-revocable-vector.py` (libargon2, libsodium, hashlib). Les tests de protocole utilisent des stores simulés ; la validation sur TPM physique après redémarrage reste à réaliser.

## Enveloppe opaque — version 1 (mode Déniabilité)

Ce format extérieur est **distinct** des signatures v1/v2/v3 et du manifeste de parties. Il ne contient aucun magic, numéro de version, identifiant de suite ou paramètre KDF public. Le lecteur doit être invoqué explicitement avec `decrypt_deniable` ; il ne tente pas une reconnaissance sans secret. Un fichier arbitraire peut être proposé, mais seul un MAC valide permet d’accepter l’enveloppe.

### Disposition

| Offset | Taille | Champ |
| --- | --- | --- |
| 0 | 32 | Sel aléatoire extérieur |
| 32 | 24 | Nonce XChaCha20 aléatoire extérieur |
| 56 | variable | Volume intérieur entier chiffré avec XChaCha20 |
| fin − 64 | 64 | Tag BLAKE2b-512 à clé |

Le volume intérieur est un volume standard v1, paranoïaque v2, Threefish v5 ou protégé RS v3, généré normalement avec ses **propres** sel, nonce, clés et tag. Son en-tête, ses indicateurs de compression et son éventuelle parité RS sont donc tous chiffrés dans la sortie publique. L’écrivain interdit tout commentaire non vide. Aucun padding extérieur ni nom original n’est stocké. Le surcoût extérieur est exactement **120 octets**. La taille minimale acceptée est 261 octets : 56 de préfixe, un volume intérieur minimal de 141 octets, 64 de tag.

Le nom habituel est `nom.extension.bin`. L’extension n’est pas requise et n’est jamais utilisée pour reconnaître le contenu. Au déchiffrement opaque, `.bin` est retiré pour le nom de sortie ; un fichier renommé sans cette extension produit `nom.decrypted`. Le nom de sortie ne doit jamais être vide, `.` ou `..`. Le traitement récursif préserve les sous-dossiers.

### Dérivation extérieure

Sérialiser comme pour v1, mais avec le domaine exact **`Tasarut/deniable/v1/password+keyfiles`**, sans octet nul final :

```text
BLAKE2b-512(
    domaine || u64(len(password UTF-8)) || password UTF-8 ||
    u64(nombre de fichiers-clés) ||
    pour chaque fichier-clé : u64(taille) || contenu
)
```

Tous les entiers sont little-endian. L’ordre et le contenu des fichiers-clés comptent ; leurs noms ne comptent pas. Utiliser le sel extérieur avec **Argon2id v1.3**, paramètres fixes **262144 Kio, 6 itérations, 4 voies, 64 octets de sortie**. Séparer `K_enc = output[0..32]` et `K_mac = output[32..64]`. Ce profil ne dépend pas de la suite intérieure. La dérivation intérieure conserve son domaine et son profil v1, v2 ou v5, avec un sel indépendant. Aucune clé extérieure n’est réutilisée pour le chiffrement intérieur.

### Chiffrement et authentification

Chiffrer le volume intérieur complet avec XChaCha20, `K_enc`, le nonce extérieur de 24 octets et le compteur initial zéro. Soit `L` la longueur du volume intérieur chiffré, égale à `taille_fichier − 120`. Calculer :

```text
tag = BLAKE2b-MAC-512(
    clé = K_mac,
    message = "Tasarut/deniable/v1/envelope\0" ||
              préfixe_extérieur[0..56] || u64(L) || ciphertext
)
```

L’octet nul final du domaine MAC est inclus. La longueur, le sel, le nonce et chaque octet de contenu sont authentifiés. Le tag est vérifié en temps constant par la primitive MAC.

### Lecture et interactions

1. Lire uniquement le préfixe et la longueur physique, vérifier la taille minimale et dériver les clés extérieures avec le profil fixe.
2. Authentifier la totalité de l’enveloppe sur le même descripteur de fichier. Aucun contenu intérieur n’est analysé ni décompressé avant succès.
3. Revenir au début, comparer de nouveau le préfixe et déchiffrer en flux dans un temporaire privé du volume intérieur. Revérifier le MAC extérieur, le tag, la longueur physique et la fin du fichier avant d’utiliser ce temporaire.
4. Appeler le lecteur v1/v2/v3 normal : correction RS éventuelle, authentification intérieure puis seconde authentification pendant le déchiffrement. Publier le texte clair seulement après succès complet, sans écrasement.

Une demande d’enveloppe avec commentaire public ou découpage est refusée. Le manifeste de parties reste reconnaissable et n’est donc pas employé. Le pont IPC interdit aussi Déchiffrement forcé avec Déniabilité : il n’existe aucun chemin contournant le MAC extérieur. Reed–Solomon peut être présent **à l’intérieur**, mais une enveloppe extérieure modifiée est refusée avant son décodage ; la récupération d’une telle corruption n’est pas prise en charge.

Les temporaires de volume intérieur sont supprimés sur une erreur gérée, les buffers privés et clés sont effacés avec `Zeroizing`, les tailles de buffers restent de 256 Kio. Une interruption brutale peut laisser un temporaire privé. La consommation de disque comprend le volume intérieur complet en plus de la sortie. Les KDF sont exécutées successivement, avec au plus 256 Mio de mémoire Argon2 à la fois.

La propriété revendiquée est l’absence de signature publique Tasarut dans la représentation opaque, sous les propriétés pseudorandom des primitives. Ce n’est ni une preuve de déniabilité face à un adversaire, ni un système de mots de passe leurres ou volumes cachés. Les longueurs, noms, extensions, dates et traces externes ne sont pas masqués. Avec compression désactivée, la taille originale peut être déduite en supposant un profil intérieur. Le nonce, le sel, le texte chiffré et le MAC ont une apparence aléatoire ; aucun test statistique n’est présenté comme une preuve de sécurité.

Le vecteur de référence `deniable-v1.hex` est généré indépendamment par `scripts/generate-deniable-vector.py` avec libargon2, libsodium et `hashlib`. Les tests vérifient la lecture et les octets exacts du chiffrement extérieur.

## Ensembles de parties — manifeste version 1

Cette enveloppe externe contient un volume v1, v2 ou v3 inchangé, découpé **après** chiffrement et protection RS. Elle ne constitue pas un format de chiffrement v4.

Un ensemble est un dossier `nom.tasarut.parts`, avec un manifeste `manifest.tasarut` et des parties nommées `000001.part` à `065536.part`. Les parties sont des tranches brutes contiguës du volume complet, sans en-tête supplémentaire. Aucun chemin ou nom fourni par le manifeste n’est utilisé : les noms sont calculés à partir des indices. Le lecteur accepte aussi un dossier renommé contenant le manifeste. Une sélection de plusieurs parties du même dossier se réduit à un seul ensemble.

### Disposition du manifeste

Tous les entiers sont little-endian.

| Offset | Taille | Champ |
| --- | --- | --- |
| 0 | 8 | ASCII `TASPART` suivi de `0x01` |
| 8 | 8 | Longueur totale du volume extérieur, u64, non nulle |
| 16 | 8 | Taille maximale des parties, u64 |
| 24 | 4 | Nombre de parties, u32 |
| 28 | 64 × nombre | Empreintes BLAKE2b-512 sans clé, dans l’ordre des parties |
| fin − 64 | 64 | MAC du manifeste |

Le moteur accepte des tailles de 1024 octets à 1 Tio ; l’interface impose des Mio entiers de 1 à 1048576. Le nombre doit être exactement `ceil(longueur / taille)`, de 1 à 65536. Toutes les parties sauf la dernière ont exactement la taille indiquée ; la dernière a `longueur − (nombre − 1) × taille` octets. La longueur du manifeste doit être exactement `28 + 64 × nombre + 64`, sans données supplémentaires. Les tailles, versions et géométries inconnues sont refusées avant allocation ou réassemblage ; le manifeste ne dépasse pas 4194396 octets.

### Liaison authentifiée

Lire l’en-tête v1/v2 du volume réassemblé, après décodage RS si nécessaire, puis dériver les clés avec les mêmes mot de passe, fichiers-clés, sel et suite que le volume. Calculer avec `K_mac` de cette suite :

```text
MAC("Tasarut/chunks/v1/manifest\0" || manifeste_sans_tag)
```

La suite standard utilise BLAKE2b-MAC-512 ; la suite paranoïaque utilise HMAC-SHA3-512. Le domaine, avec son octet nul final, sépare le MAC du manifeste du MAC du volume. Les empreintes ordonnées authentifient le contenu exact de toutes les parties, y compris les commentaires publics et la parité RS extérieure. Une substitution de parties entre volumes aléatoires, un changement d’ordre ou une modification des empreintes est refusé par les empreintes ou par le MAC. Le nom externe du dossier n’est pas authentifié.

Les parties sont copiées et vérifiées en flux dans un temporaire chiffré privé. Ensuite, le MAC du manifeste est vérifié, puis le chemin normal authentifie le volume intérieur en deux passes avant publication du texte clair. L’inspection sans secret vérifie les empreintes mais pas le MAC : les métadonnées affichées restent non authentifiées. La récupération forcée exige également un ensemble complet dont le manifeste est authentifié ; elle conserve son statut de sortie non certifiée.

La vérification extérieure est stricte : une erreur d’empreinte bloque le traitement avant une éventuelle correction RS. Cette version ne propose pas de récupération de parties endommagées ou manquantes. Les liens symboliques des parties ou du manifeste sont refusés.

### Publication

Écrire toutes les parties et le manifeste dans un dossier temporaire du même dossier parent, synchroniser chaque fichier, supprimer le temporaire de volume complet, puis renommer le dossier avec `renameat2(RENAME_NOREPLACE)` sur Linux. Aucun ensemble incomplet n’est rendu visible au nom de sortie. Une destination existante, même un dossier vide, est refusée. Sur erreur gérée, le dossier de préparation est supprimé. La durabilité du renommage après une panne électrique n’est pas garantie par une synchronisation du dossier parent ; une interruption brutale peut laisser une préparation temporaire cachée.

## Disposition standard v1

Les entiers sont en little-endian.

| Offset | Taille | Champ |
| --- | --- | --- |
| 0 | 8 | `TASARUT` suivi de `0x01` |
| 8 | 1 | Flags : bit 0 = compression Zstandard ; autres bits refusés |
| 9 | 32 | Sel aléatoire |
| 41 | 24 | Nonce XChaCha20 aléatoire |
| 65 | 8 | Taille du fichier original, u64 |
| 73 | 4 | Longueur du commentaire UTF-8, u32, maximum 65 536 |
| 77 | variable | Commentaire public |
| suivant | variable | Contenu chiffré, éventuellement précompressé |
| fin − 64 | 64 | Tag BLAKE2b-512 à clé |

Le nom d’origine n’est pas contenu dans le volume. Le nom de sortie habituel le conserve extérieurement. La taille originale et la présence de compression sont publiques, mais authentifiées ; l’inspection avant vérification ne doit pas être considérée comme fiable.

Le format normal est reconnaissable ; il ne fournit aucune déniabilité.

## Dérivation standard v1

Calculer BLAKE2b-512 sans clé sur la concaténation :

```text
"Tasarut/v1/password+keyfiles"
u64(len(password UTF-8)) || password UTF-8
u64(nombre de fichiers-clés)
pour chaque fichier-clé, dans l’ordre :
    u64(taille) || contenu complet
```

Tous les entiers sont little-endian. Aucun nom ou chemin de fichier-clé n’est inclus. Il n’y a pas de normalisation Unicode du mot de passe.

Passer les 64 octets obtenus à **Argon2id v1.3**, avec le sel public de 32 octets et les paramètres fixes :

- mémoire : 65 536 Kio ;
- itérations : 3 ;
- parallélisme : 4 voies ;
- sortie : 64 octets.

Séparer la sortie en `K_enc = output[0..32]` et `K_mac = output[32..64]`.

## Chiffrement standard v1

Si demandé, compresser le fichier original en un flux Zstandard de niveau 3. Chiffrer le flux (ou le fichier sans compression) avec XChaCha20, `K_enc`, le nonce public et le compteur initial fourni par RustCrypto `chacha20` 0.9 (zéro).

Calculer :

```text
tag = BLAKE2b-MAC-512(
    clé = K_mac,
    message = volume[0..73] || ciphertext
)
```

La longueur du commentaire et son contenu sont intentionnellement exclus. Changer la longueur en déplaçant correctement le contenu chiffré n’invalide donc pas le tag.

## Disposition paranoïaque v2 — suite 1

| Offset | Taille | Champ |
| --- | --- | --- |
| 0 | 8 | `TASARUT` suivi de `0x02` |
| 8 | 1 | Identifiant de suite : `0x01` uniquement |
| 9 | 1 | Flags : bit 0 = compression Zstandard ; autres bits refusés |
| 10 | 32 | Sel aléatoire |
| 42 | 24 | Nonce XChaCha20 aléatoire |
| 66 | 16 | IV initial Serpent-CTR, interprété comme un compteur 128 bits big-endian |
| 82 | 8 | Taille du fichier original, u64 little-endian |
| 90 | 4 | Longueur du commentaire UTF-8, u32 little-endian, maximum 65 536 |
| 94 | variable | Commentaire public |
| suivant | variable | Contenu chiffré par la cascade |
| fin − 64 | 64 | Tag HMAC-SHA3-512 |

Le générateur d’IV Serpent produit 8 octets aléatoires suivis de 8 octets nuls. Le compteur **128 bits complet** s’incrémente en big-endian, un bloc de 16 octets à la fois. Le premier bloc de keystream est `Serpent-256(K_serpent, IV)` ; pas de padding du contenu, les octets de keystream inutilisés sont conservés entre appels. Le lecteur accepte un IV 128 bits quelconque, dont l’intégrité est vérifiée avant usage.

## Dérivation et chiffrement paranoïaques v2

La sérialisation du mot de passe et des fichiers-clés est celle de v1, mais le domaine initial est **`Tasarut/v2/paranoid/password+keyfiles`**. Le préhash BLAKE2b-512 reste un prétraitement de la dérivation, pas l’authentification du volume.

Paramètres fixes **Argon2id v1.3** :

- mémoire : **262 144 Kio** ;
- itérations : **6** ;
- parallélisme : **4 voies** ;
- sortie : **128 octets**.

Les clés sont séparées :

```text
K_xchacha = output[0..32]
K_serpent = output[32..64]
K_mac     = output[64..128]
```

Le contenu est éventuellement compressé avec Zstandard niveau 3, puis chiffré :

```text
intermediate = XChaCha20(K_xchacha, nonce, counter=0, plaintext_or_zstd)
ciphertext   = Serpent-256-CTR128BE(K_serpent, IV, intermediate)
tag          = HMAC-SHA3-512(K_mac, volume[0..90] || ciphertext)
```

Il s’agit bien de **Serpent avec une clé de 256 bits**, pas de son initialisation 128 bits par défaut. L’implémentation utilise RustCrypto `serpent` 0.6 (opérations bitslice) et `ctr` 0.10. XChaCha20 reste RustCrypto `chacha20` 0.9.

SHA3-512 est la variante standardisée **FIPS 202**, pas Keccak-512. Les versions v1/v2 ont toutes deux un tag de 64 octets. Les commentaires et leur longueur restent exclus de l’authentification. Le sel, les deux nonces/IV, la taille, la version, la suite et les flags sont inclus. Il n’y a pas d’essai automatique d’un autre mode après un échec d’authentification.

Les paramètres KDF ne sont pas des entiers libres dans l’en-tête : la suite choisit un profil connu et borné. Le profil v2 utilise plus de mémoire et de temps même avant de savoir si le mot de passe est correct.

## Enveloppe Reed–Solomon v3

Cette couche ne change ni le chiffrement, ni les paramètres KDF, ni le MAC du volume intérieur. Sans l’option Reed–Solomon, les octets des formats v1/v2 restent identiques aux versions précédentes.

### Code et ordre des symboles

- Code raccourci systématique **RS(136,128)** sur **GF(256)**.
- Polynôme primitif : **`0x11d`**, élément primitif **α = 2**.
- Polynôme générateur : **∏(x + αⁱ)** pour **i = 0…7**.
- Ordre des coefficients : du degré le plus élevé au plus faible, pour la division polynomiale.
- Mot de code : **128 octets de données suivis de 8 octets de parité**.
- Correction de substitutions à positions inconnues : **au plus 4 par mot de code**. Les effacements connus ne sont pas exploités dans cette version.
- Bibliothèque Rust : `reed-solomon` 0.2.1, sans option `unsafe_indexing`.

### Disposition physique

Le premier bloc de 136 octets est un descripteur protégé par le même code. Ses 128 octets de données sont :

| Offset décodé | Taille | Champ |
| --- | --- | --- |
| 0 | 8 | `TASARUT` suivi de `0x03` |
| 8 | 8 | Longueur exacte du volume intérieur, u64 little-endian |
| 16 | 112 | Réservé, tous les octets nuls |

Les blocs physiques suivants protègent successivement les octets du volume intérieur v1/v2 **complet**, tag inclus. Le dernier bloc de données est complété par des zéros jusqu’à 128 octets ; le lecteur vérifie ce remplissage après correction et ne l’expose pas au lecteur cryptographique.

```text
physical_length = 136 × (1 + ceil(inner_length / 128))
physical_block 0 = RS(descriptor[128])
physical_block i+1 = RS(inner_volume[128×i .. 128×(i+1)], padded with zeros)
```

La géométrie doit correspondre exactement à la taille du fichier physique. Les données supplémentaires, blocs manquants et troncatures sont refusés. La longueur est contrôlée par des calculs bornés ; elle ne détermine pas une allocation mémoire de cette taille. Un volume v3 ne peut pas contenir une autre enveloppe v3.

### Correction et authentification

Le descripteur est décodé avant de décider du format, même si une corruption de l’octet de version le fait ressembler à v1/v2. Le lecteur corrige chaque bloc avant de remettre ses octets au parseur et au MAC cryptographiques. Il offre une vue logique `Read + Seek` du volume intérieur, avec des buffers bornés, pour conserver les deux passes de vérification.

Le MAC/HMAC authentifie toujours le **volume intérieur** comme défini pour v1/v2. La parité et le descripteur de l’enveloppe ne sont pas une authentification cryptographique. La longueur déclarée, la géométrie et les octets réservés/remplis doivent être cohérents, puis l’intégralité du contenu cryptographique décodé doit être authentifiée. Le fait de décoder un mot de code valide ne permet jamais d’ignorer un MAC invalide.

Les commentaires sont protégés contre les erreurs accidentelles, mais restent publics et exclus du MAC : un attaquant peut modifier leur texte/longueur puis recalculer les blocs et leur parité, sans connaître le secret. Cette propriété est volontairement conservée.

La correction ne réécrit jamais le fichier source. Le compte rendu est un instantané des corrections de la première passe complète, après vérification du MAC ; il inclut le descripteur, les commentaires, les données, le tag et la parité corrigés. Les corrections de la seconde passe ne sont pas comptées une deuxième fois. Les champs `correctedBlocks` et `correctedBytes` sont affichés uniquement pour une opération réussie.

En mode normal, cette couche ne gère pas la disparition ou l’insertion d’octets, ni leur décalage. Au-delà de la capacité du code, un échec ou une mauvaise correction est possible : le MAC reste l’arbitre de l’intégrité cryptographique. La récupération forcée ci-dessous est un chemin explicitement distinct.

## Déchiffrement commun

1. Valider le magic, les flags, la borne du commentaire et la taille minimale.
2. Dériver les clés avec les paramètres fixes ; aucune quantité mémoire issue du volume n’est acceptée.
3. Authentifier entièrement l’en-tête canonique et le contenu chiffré avec comparaison de tag en temps constant.
4. Revenir au début du contenu chiffré sur le même descripteur. Déchiffrer en flux vers un temporaire, en recalculant le MAC. Pour v2, retirer d’abord Serpent-CTR puis XChaCha20.
5. Décompresser si nécessaire, en limitant la production à `taille_originale + 1`, et vérifier la taille exacte.
6. Vérifier le second MAC, le tag relu et l’absence de données supplémentaires.
7. Synchroniser puis publier le temporaire sans écrasement.

Dans ce chemin normal, une erreur de mot de passe, de fichiers-clés ou d’intégrité ne publie pas de fichier déchiffré.

## Récupération forcée — sans nouveau format

L’API `force_decrypt` accepte les formats v1/v2/v3, le même mot de passe et les mêmes fichiers-clés. Le profil Argon2id, les clés et la cascade sont inchangés. Un en-tête cryptographique de version/suite connue, avec ses champs de taille fixe présents et un commentaire borné à 64 Kio, reste requis. Le commentaire peut être affiché avec remplacement des séquences UTF-8 invalides. La présence du tag n’est pas requise pour lire cet en-tête en récupération.

### Vue logique v3 permissive

- Tenter la correction du descripteur et des blocs RS.
- Si le descripteur n’est pas corrigeable mais garde son magic v3 et une longueur utilisable, exploiter ses champs bruts et signaler ses dommages. Les valeurs ne deviennent pas fiables pour autant.
- Autoriser une longueur physique plus courte que celle déclarée ; borner la vue logique aux octets de données effectivement présents.
- Pour un dernier mot de code incomplet avec au plus 8 positions finales absentes, utiliser ces positions comme effacements connus. Sinon utiliser uniquement les octets présents.
- Si un bloc complet n’est pas corrigeable, remettre ses 128 octets de données bruts au déchiffreur et enregistrer son intervalle logique. Cela conserve les décalages des blocs suivants quand aucune insertion/suppression n’a eu lieu.
- Ne pas inventer des blocs ou des octets de texte chiffré pour une queue absente. Le remplissage et les données supplémentaires non canoniques sont signalés plutôt que certifiés.
- Compter chaque bloc une seule fois, y compris lors d’un retour en arrière pour lire le tag. Les intervalles enregistrés sont plafonnés à 128.

### Texte chiffré non compressé

La taille originale déclarée définit la longueur attendue du contenu chiffré. Lire au plus cette longueur, les octets disponibles et la limite de sortie choisie. Appliquer la cascade habituelle et conserver le résultat. Si tout le contenu attendu est présent, tenter de lire le tag à sa position attendue et vérifier le MAC ; sinon signaler le tag absent ou l’arrêt à la limite. Une taille déclarée corrompue rend cette délimitation incertaine : le résultat reste non authentifié.

### Texte chiffré compressé

Utiliser le décodeur Zstandard brut pour connaître le nombre exact d’octets consommés jusqu’à la fin de la première trame. Le MAC est mis à jour uniquement sur les octets chiffrés correspondant aux entrées réellement consommées par le décodeur, pas sur le tag éventuellement prélu dans le même buffer. Lorsque la trame se termine, rechercher le tag à cette position exacte. Cela permet la récupération d’une trame entière même si son tag a disparu.

Sur une erreur Zstandard ou une fin de flux avant la fin de trame, conserver les sorties des appels réussis précédents. Ne pas deviner une position de tag ou tenter un décodage arbitraire à un autre offset. `WindowLogMax(27)` borne la fenêtre à 128 Mio. La limite de sortie vaut 4 Gio par défaut, au plus 1 Tio ; elle est indépendante de la taille non authentifiée du fichier déclaré.

### Rapport et publication

`ForceReport` contient toujours `authenticated: false`, même si `macStatus: valid`. La récupération forcée n’offre pas les mêmes vérifications de bout en bout que le chemin normal. Les autres états du MAC sont `invalid`, `missing` et `notChecked`. Le rapport distingue la quantité récupérée, la longueur déclarée, l’arrêt à la limite, l’échec de décompression, les anomalies de structure et les dommages Reed–Solomon.

`partial` indique une sortie plus courte/différente de la longueur déclarée, un arrêt à la limite ou une décompression incomplète ; ce n’est pas une preuve de validité des octets qui ont été récupérés. Les octets manquants du conteneur v3 peuvent appartenir au tag plutôt qu’au texte chiffré, donc un conteneur tronqué ne signifie pas nécessairement un fichier déchiffré plus court.

Tauri ajoute le suffixe `.recovered` et présente le résultat comme récupération non authentifiée. Les erreurs de fichiers, les collisions de noms, l’absence de données récupérables d’un fichier non vide et les en-têtes inutilisables ne publient pas de sortie. Le temporaire reste nettoyé sur une erreur gérée. La taille du fichier source doit rester stable jusqu’à publication. La récupération ne modifie pas le volume source et ne produit pas de rapport annexe sur disque.

## Tests et limites

Les vecteurs `crates/tasarut-core/test-vectors/*.hex` sont produits indépendamment par `scripts/generate-vectors.py`, à partir de libargon2, libsodium (XChaCha20, compteur zéro), libgcrypt (Serpent-256-CTR) et Python hashlib/hmac. Le script n’importe pas le code Tasarut.

Ces vecteurs vérifient le chiffrement exact, la continuité du flux entre écritures non alignées et la lecture v1/v2. Les tests complémentaires couvrent les fichiers vides, la compression, les gros buffers, les secrets incorrects, les changements de suite/version, les altérations, les troncatures et la modification libre des commentaires. Un audit indépendant et le fuzzing restent à faire.
