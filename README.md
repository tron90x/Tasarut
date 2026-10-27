# 🔑 Tasarut

Application de bureau pour le **chiffrement individuel des fichiers**, avec une interface sombre et moderne, disponible en **anglais, français et kabyle**.

**Tauri 2 + TypeScript/Vite** pour l’interface ; **Rust** pour la cryptographie, les accès aux fichiers et le traitement en arrière-plan. Aucun compte ni service distant n’est nécessaire.

## Version 0.4 — modes avancés, découpage et enveloppe opaque

Cibles : **Fedora**, **Ubuntu** et ses dérivées, notamment **Linux Mint**. Les paquets natifs DEB/RPM sont configurés et les métadonnées AppStream sont incluses. La diffusion par les magasins sera une étape de publication distincte ; voir [Distribution Linux](docs/LINUX.md).

| Fonctionnalité | État |
| --- | --- |
| Chiffrement et déchiffrement individuels XChaCha20 | Implémentés |
| Choix Threefish-1024 à 80 tours, CTR128BE et HMAC-SHA3-512 | Implémenté ; format v5 et v4 suite 3 avec TPM |
| Authentification BLAKE2b-512 à clé, construction encrypt-then-MAC | Implémentée |
| Dérivation Argon2id v1.3 : 64 Mio, 3 itérations, 4 voies | Implémentée |
| Générateur de mots de passe, 16 à 128 caractères | Implémenté |
| Fichiers-clés supplémentaires au mot de passe | Implémentés |
| Commentaires publics, affichés sans déchiffrement | Implémentés |
| Compression Zstandard avant chiffrement | Implémentée |
| Traitement récursif, un volume par fichier, arborescence préservée | Implémenté |
| Glisser-déposer, sélection multiple, résultats par fichier | Implémentés |
| Progression par octet et par étape de traitement | Implémentée |
| Annulation coopérative et nettoyage des sorties incomplètes | Implémentés |
| Raccourcis clavier et aide multilingue accessible avec F1 | Implémentés |
| Profils d’utilisation, bibliothèque locale et échanges JSON | Implémentés |
| Suppression renforcée de volumes et compte rendu TRIM Linux | Implémentés |
| Détection préalable du stockage des volumes : NVMe, SSD/flash déclaré, HDD déclaré, mixte ou indéterminé | Implémentée sous Linux |
| Volumes v4 révocables par suppression d’un secret TPM2 NV | Implémentés ; validation matérielle à réaliser |
| Anglais, français, kabyle en alphabet latin | Implémentés ; traduction kabyle à relire |
| Six thèmes visuels, paysages locaux, verre et palettes propres à chaque ambiance | Implémentés ; choix mémorisé |
| Mode paranoïaque XChaCha20 → Serpent-256-CTR + HMAC-SHA3-512 | Implémenté |
| Profil paranoïaque Argon2id : 256 Mio, 6 itérations, 4 voies | Implémenté |
| Détection automatique standard v1 / paranoïaque v2 / enveloppe RS v3 | Implémentée |
| Reed–Solomon : 8 octets supplémentaires pour 128 octets | Implémenté |
| Correction avant authentification et compte rendu des octets/blocs corrigés | Implémentés |
| Déchiffrement forcé / récupération de fichiers endommagés | Implémenté |
| Rapports de récupération, sorties .recovered et limite par fichier | Implémentés |
| Découpage des volumes en parties et réassemblage automatique | Implémentés |
| Déniabilité : enveloppe opaque sans signature publique Tasarut | Implémentée |

Les cinq modes avancés sont disponibles dans l’écran **Modes avancés**. Le format est propre à Tasarut, sans compatibilité avec Picocrypt. Cette première implémentation n’a pas encore été auditée indépendamment.

## Lancer l’application

Prérequis : Rust stable, Node.js **22.12+** (ou 20.19+) et les [dépendances système de Tauri](https://v2.tauri.app/start/prerequisites/).

Sur Ubuntu / Linux Mint :

```bash
sudo apt install build-essential pkg-config libwebkit2gtk-4.1-dev \
  libgtk-3-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev patchelf
```

Sur Fedora :

```bash
sudo dnf install gcc gcc-c++ make pkgconf-pkg-config webkit2gtk4.1-devel \
  gtk3-devel openssl-devel libappindicator-gtk3-devel librsvg2-devel patchelf
```

Depuis le dossier `Tasarut` :

```bash
npm ci
npm run tauri -- dev
```

Pour visualiser seulement l’interface dans le navigateur :

```bash
npm run dev
```

Ouvrir `http://localhost:1420`. Le navigateur affiche explicitement un aperçu : le traitement de fichiers nécessite l’application Tauri. Le générateur reste disponible dans l’aperçu grâce à Web Crypto.

### Essayer le Flatpak local

Un premier profil Flatpak **x86_64**, avec GNOME Platform 51 et les portails de
sélection de fichiers, est disponible pour les essais. Il reconditionne le
binaire déjà compilé et s'installe séparément du DEB sous le nom
**Tasarut (Flatpak local)** :

```bash
python3 scripts/build-flatpak-local.py --install
flatpak run --user org.example.Tasarut
```

Le fichier est produit dans `target/flatpak/`. L'identifiant `org.example.Tasarut`
est réservé aux essais locaux. Le TPM reste indisponible avec les permissions
par défaut et TRIM n'est pas qualifié dans ce confinement. Voir
[Flatpak local : installation, permissions et résultats](docs/FLATPAK.md).

## Utilisation

1. Choisir **Chiffrer** ou **Déchiffrer**.
2. Ajouter des fichiers, déposer des fichiers dans la fenêtre, ou ajouter un dossier. Le bouton d’ajout de dossier active le mode récursif. Pour déposer un dossier, activer d’abord **Récursivement**.
3. Saisir le mot de passe et, pour chiffrer, le confirmer. Le générateur peut remplir les deux champs.
4. Ajouter éventuellement des fichiers-clés. **Leur contenu et leur ordre doivent être identiques au déchiffrement** ; leurs noms peuvent changer. Ils complètent le mot de passe, ils ne le remplacent pas.
5. Au chiffrement, activer éventuellement **Mode paranoïaque**, **Reed–Solomon**, **Découper en parties**, la compression et un commentaire public.
6. Choisir un dossier de sortie et lancer l’opération.

Chaque fichier produit un volume `nom.extension.tasarut`. Le déchiffrement retire cette extension ; un volume renommé sans cette extension produit `nom.decrypted`. Les sous-dossiers sont conservés lors du traitement récursif. Les fichiers originaux ne sont pas supprimés. En cas de collision de noms, le fichier concerné est refusé et les autres continuent.

Quand un volume est ajouté, son commentaire apparaît sans demander de mot de passe. Cliquer sur les autres volumes de la liste pour consulter leurs commentaires.

### Choisir Threefish-1024

Dans **Options des fichiers → Algorithme de chiffrement**, choisir
**XChaCha20 — par défaut** ou **Threefish-1024**. Threefish utilise ses
**80 tours complets**, un bloc et une clé de 1024 bits, un tweak indépendant
de 128 bits, un compteur CTR128BE et HMAC-SHA3-512 avec une clé distincte.
La dérivation Argon2id utilise **256 Mio, 6 itérations et 4 voies**.

Le choix est enregistré dans les profils et détecté automatiquement au
déchiffrement. Compression, RS, découpage et enveloppe opaque sont compatibles ;
le mode révocable utilise v4 suite 3. La cascade paranoïaque reste une option
distincte de XChaCha20. Une plus grande clé ne démontre pas une meilleure
sécurité que XChaCha20. Voir [Threefish : construction et tests](docs/THREEFISH.md).

### Thèmes et ambiances

Choisir une ambiance dans le **sélecteur de la barre supérieure**, ou ouvrir
**Thèmes** dans la navigation pour comparer les six paysages : **Par défaut**,
**Désert**, **Montagnes de Kabylie**, **Océan**, **Espace** et **Pôle Nord**.
Chaque thème possède son fond illustré original, sa palette et ses réglages
de verre, de flou, de bordures et d'ombres. Le thème par défaut conserve le
graphite et le vert menthe de Tasarut, avec une lisibilité affinée.

Les fonds sont intégrés et disponibles **hors ligne**. Le choix est mémorisé
sur l'appareil sous `tasarut-theme-v1`, indépendamment des profils et du
chiffrement. Le clavier et les préférences de mouvement/transparence réduits
sont pris en charge. Voir [Thèmes et paysages](docs/THEMES.md) pour les
réglages et la validation visuelle.

### Volumes révocables TPM2 — v4

Ce mode conserve **un secret aléatoire indépendant de 32 octets par volume dans un index NV du TPM2**, et non dans un coffre de clés sur SSD. Le mot de passe et les fichiers-clés donnent l’autorisation de lecture de cet index ; ils ne permettent pas de régénérer le secret supprimé. Révoquer l’index rend toutes les copies du volume portant ce même identifiant indéchiffrables sur ce TPM, tant qu’aucune copie du secret ou des clés dérivées n’a été capturée.

#### Préparation du système

Le mode nécessite Linux, un TPM **2.0 physique et non restaurable**, l’accès à `/dev/tpmrm0` ou `/dev/tpm0`, et les commandes `tpm2_nvdefine`, `tpm2_nvwrite`, `tpm2_nvwritelock`, `tpm2_nvread`, `tpm2_nvreadpublic`, `tpm2_nvundefine` et `tpm2_getcap` du paquet **tpm2-tools**. L’interface indique les dépendances détectées et permet de **Vérifier le TPM**. L’autorisation propriétaire et la capacité NV restent vérifiées pendant l’opération ; leur simple détection ne garantit pas qu’une création soit autorisée.

Un swap persistant est refusé pour éviter que les processus de chiffrement et les outils TPM y déposent des secrets récupérables après déchiffrement du disque. Le zram sans stockage de secours est accepté. Les core dumps sont désactivés pour les opérations TPM et leurs processus enfants. Tasarut ne modifie pas le swap, ne réinitialise pas le TPM, n’élève pas les privilèges et ne propose pas de remplacement par un coffre logiciel. Un TPM virtuel dont l’état peut être restauré avec une VM ne fournit pas cette propriété : le contrôle logiciel du périphérique ne prouve pas à lui seul qu’il est physique.

La perte ou la réinitialisation du TPM peut rendre **tous** les volumes concernés illisibles. Les clés capturées avant révocation, les dumps mémoire, l’hibernation, les instantanés de TPM virtuel, les originaux en clair et les sorties déjà déchiffrées ne sont pas retirés par une révocation. Le TPM et les hypothèses de protection de ses états restent une partie du modèle de confiance.

#### Chiffrer et déchiffrer

1. Activer **Volume révocable TPM** au chiffrement. Choisir éventuellement compression, mode paranoïaque et Reed–Solomon.
2. Saisir et confirmer le mot de passe, puis choisir les fichiers-clés habituels.
3. Si la hiérarchie propriétaire du TPM utilise une autorisation non vide, la saisir dans **Autorisation propriétaire du TPM**. Elle est distincte du mot de passe du volume et n’est enregistrée ni dans un profil ni dans le fichier chiffré.
4. Choisir la sortie et lancer. Chaque fichier produit `nom.extension.tasarut.rev`. Le contenu est chiffré **directement en flux avec le secret TPM** : aucun temporaire de volume intérieur protégé par le seul mot de passe n’est créé. Un temporaire interrompu reste donc également lié au secret TPM.
5. Au déchiffrement, le format v4 est détecté automatiquement ; le même TPM, le mot de passe et les fichiers-clés sont nécessaires. Le lecteur authentifie intégralement avant de produire la sortie privée, puis revérifie le MAC pendant le déchiffrement avant publication.

Le profil extérieur de dérivation d’autorisation est fixe : **Argon2id v1.3, 256 Mio, 6 itérations, 4 voies**. Les clés de contenu sont dérivées séparément de cette matière, du secret TPM et de l’identifiant du volume. Le mode standard emploie XChaCha20 + BLAKE2b à clé ; le mode paranoïaque emploie la cascade et HMAC-SHA3-512. La protection RS peut envelopper le volume v4 entier et est corrigée avant authentification. Les commentaires publics, l’enveloppe opaque, le découpage et la récupération forcée sont incompatibles avec cette version du mode.

Une erreur ou une annulation avant publication entraîne une demande de retrait de l’index alloué. Si ce nettoyage matériel échoue, aucun résultat n’est déclaré publié et l’erreur retourne **l’index à conserver pour nettoyage administrateur**. Un arrêt brutal peut laisser un index orphelin ou un temporaire chiffré ; la capacité NV est limitée et les index ne sont jamais recyclés en remplaçant arbitrairement une entrée existante.

#### Révoquer

Ajouter les volumes v4, saisir le mot de passe, les fichiers-clés et si nécessaire l’autorisation propriétaire, puis choisir **Révoquer les clés des volumes sélectionnés**. Le dialogue liste les chemins, identifiants et index publics. L’aperçu natif est valable une fois pendant dix minutes et conserve les identités des fichiers examinés.

Après confirmation, le moteur recontrôle le fichier et vérifie le **MAC complet**, puis le fournisseur lit l’enregistrement correspondant, contrôle ses droits et son verrou, vérifie l’identifiant, retire uniquement cet index et relit sa partie publique pour **confirmer son absence**. Un index absent, inaccessible, une autorisation incorrecte ou un volume modifié n’est pas présenté comme une révocation confirmée. Le rapport conserve les résultats par volume. Une annulation arrête les suivants ; un retrait TPM déjà engagé peut terminer et son résultat réel est rapporté.

Les fichiers chiffrés restent sur disque ; la révocation ne les efface pas physiquement. La suppression renforcée reste une action séparée, et supprimer un fichier chiffré ne retire pas automatiquement sa clé TPM.

L’espace NV utilisé est `0x015a0000–0x015affff`. Un enregistrement est constitué de l’identifiant public de 32 octets et du secret de 32 octets. Il exige `AUTHREAD | AUTHWRITE | WRITEDEFINE | NO_DA`, puis `WRITTEN | WRITELOCKED`, une taille de 64 octets et SHA-256 ; les droits OWNERREAD/OWNERWRITE et les attributs supplémentaires sont refusés. Les outils sont recherchés dans les chemins système, leur cible doit être possédée par root et non modifiable par groupe/autres ; le TCTI est fixé au périphérique local. Authentifications et enregistrements transitent par des **memfds anonymes**, jamais par des fichiers de clés ou des arguments de commande en clair. Les commandes et sorties sont bornées et aucun stderr contenant potentiellement des données de contexte n’est exposé comme preuve de révocation.

Les tests utilisent des fournisseurs mémoire et des échanges TPM simulés, jamais un index réel. Aucun TPM ni tpm2-tools n’est disponible dans l’environnement de développement ayant validé cette implémentation. Une validation native sur TPM physique, notamment après redémarrage, erreurs d’autorisation et saturation NV, reste nécessaire avant qualification matérielle. Voir le [format v4](docs/FORMAT.md) et la [procédure de qualification sur TPM physique](docs/TPM-QUALIFICATION.md), avec scénarios, résultats attendus et modèle de compte rendu.

### Suppression renforcée avec compte rendu

1. Ajouter les volumes à la liste, puis cliquer sur **Suppression renforcée** sous les fichiers. La préparation ne supprime rien.
2. Examiner les chemins exacts : chaque volume ou ensemble de parties est affiché avec la liste de ses fichiers et les refus éventuels. La section **Détection du stockage avant suppression** indique le stockage déclaré et la capacité discard pour chaque système de fichiers concerné. La **liste JSON complète avant confirmation** permet de consulter les listes dont seuls les 200 premiers chemins sont affichés dans le résumé.
3. Choisir éventuellement **Demander TRIM après la suppression**, désactivé par défaut. Le dialogue affiche les systèmes de fichiers concernés.
4. Cliquer sur **Supprimer définitivement les fichiers listés**, ou fermer le dialogue pour abandonner l’aperçu. Aucun raccourci de lancement ne traverse ce dialogue. Il n’y a pas de corbeille.
5. Lire le **Dernier compte rendu de suppression** : fichiers retirés, tailles logiques, chemins encore présents ou non traités, vérification de disparition, synchronisation des dossiers et résultat TRIM. Un compte rendu JSON complet est consultable et copiable dans l’interface.

La reconnaissance des volumes standard v1/v2/v3 repose sur leur format, sans mot de passe et sans garantie d’authenticité cryptographique du contenu. Pour les enveloppes opaques, choisir **Déchiffrer**, activer **Déniabilité**, fournir le mot de passe et les fichiers-clés, puis préparer la suppression : l’enveloppe extérieure est authentifiée en flux, sans créer de temporaire déchiffré. Les secrets ne sont pas conservés dans l’aperçu ou le rapport.

La préparation produit un jeton opaque, utilisable une seule fois pendant dix minutes, lié à la sélection native examinée. Le moteur conserve les identités de fichiers et des références de dossiers ; la confirmation ne fournit pas de nouveaux chemins à supprimer. Les métadonnées et les identités sont revérifiées avant le retrait. Les chemins traversant des liens symboliques, les fichiers-clés sélectionnés et les fichiers possédant plusieurs liens physiques sont refusés.

Un ensemble de parties exige un descripteur valide et ne peut contenir que le manifeste et les parties numérotées annoncées. Des parties déjà absentes sont signalées ; les entrées inattendues ou sous-dossiers provoquent un refus. Le moteur retire seulement les fichiers listés, garde le manifeste pour la fin et ne supprime le dossier de l’ensemble qu’une fois vide. Aucun effacement récursif général d’un dossier utilisateur n’est effectué. Les points de montage distincts sont refusés.

Chaque entrée est déplacée temporairement vers un nom unique dans son dossier ancré, puis son identité est contrôlée avant le retrait. Une entrée substituée est restaurée sans écraser une nouvelle entrée. Si sa restauration échoue, elle est conservée au chemin indiqué par **fichier déplacé conservé ici** dans le rapport. Comme les autres opérations de Tasarut, cette fonction ne constitue pas une isolation contre un adversaire local modifiant simultanément le système de fichiers ; les changements détectés ne sont pas supprimés comme les fichiers examinés.

L’opération peut être annulée via le bouton ou **Ctrl + .**. Les fichiers déjà supprimés restent supprimés ; les suivants sont conservés. Une annulation peut laisser un ensemble de parties incomplet, dont le manifeste reste présent si l’arrêt intervient avant son retrait. La fermeture de la fenêtre est suspendue pendant le traitement. Les champs de mot de passe sont vidés à sa fin et la sélection est actualisée selon les chemins encore présents. Les compteurs mesurent la **taille logique des fichiers retirés**, pas des octets écrasés sur le stockage.

#### TRIM : portée et limites

La détection est réalisée **avant confirmation, sur le stockage des fichiers sélectionnés**, plutôt qu'en classant tout le PC au lancement. Elle lit uniquement les informations Linux de `/sys/dev/block` : une partition est reliée à son disque et les dépendances bloc sont suivies pour LUKS/LVM et RAID. L'aperçu distingue **NVMe non rotatif**, **non rotatif (SSD/flash)**, **rotatif (HDD déclaré)**, **mixte** et **indéterminé**, avec les noms des périphériques contenant les fichiers et sous-jacents. Les mêmes informations sont relues dans le compte rendu et incluses dans les JSON sous `storage`.

Ces catégories reposent sur les déclarations du noyau (`queue/rotational`), pas sur une preuve du matériel physique. Les ponts USB et les disques virtuels peuvent masquer le support. Les périphériques virtuels sans dépendance physique identifiable, les topologies incomplètes/inaccessibles, Btrfs (notamment multi-périphériques), tmpfs, overlay et les systèmes de fichiers sans correspondance bloc fiable restent **indéterminés**. Le parcours est borné à 64 nœuds et 16 niveaux ; aucune commande privilégiée ou écriture sur le stockage n'est utilisée pour cette détection.

La capacité discard est observée sur la **file bloc effective contenant les fichiers** (`queue/discard_max_bytes`) : un SSD sous LUKS peut être identifié alors que cette chaîne n'annonce pas discard. L'interface distingue une capacité annoncée, non annoncée ou indéterminée. Elle ne déduit pas la prise en charge de FITRIM ni les permissions à partir du seul type SSD/NVMe. La suppression contrôlée reste disponible sur HDD et lorsque le support est indéterminé ; TRIM reste une demande facultative, désactivée par défaut, dont le résultat est vérifié à l'exécution. Cette détection n'est pas un prérequis des volumes révocables TPM.

Sous Linux, la demande utilise **FITRIM** sur un descripteur de dossier du système de fichiers concerné, après synchronisation. Elle ne lance ni shell, ni commande ATA/NVMe d’effacement du périphérique entier, ni élévation automatique de privilèges. Des droits administrateur peuvent être nécessaires ; un refus de permissions est affiché dans le compte rendu. L’appui sur un système de fichiers ou sur la chaîne de stockage peut également être absent, notamment selon le système de fichiers, le pilote ou le chiffrement de disque.

TRIM concerne les **blocs libres du système de fichiers entier**, pas seulement les volumes choisis. Le rapport distingue **non demandé**, **aucune suppression**, **annulé**, **demande acceptée par le noyau**, **droits insuffisants**, **non pris en charge** et **échec**. La longueur éventuellement signalée par le noyau est celle de cette demande globale ; elle ne mesure pas les cellules physiques effacées et ne peut pas être attribuée uniquement aux fichiers supprimés.

**L’effacement physique n’est jamais déclaré vérifié** (`physicalErasureVerified: false`). Le wear leveling, les instantanés, les journaux, les copies, les caches ou des descripteurs ouverts par d’autres processus peuvent conserver des données ou retarder la libération des blocs. Aucun passage d’écrasement n’est ajouté comme prétendue garantie SSD/NVMe. Les originaux en clair et les autres copies sont hors de cette suppression. La révocation des secrets des [volumes TPM2 v4](#volumes-révocables-tpm2--v4) est une action distincte de cette suppression.

Les limites sont de 1000 volumes, 65537 fichiers et 16 Mio de chemins listés par aperçu. Les tests n’envoient aucun TRIM réel : leurs résultats noyau sont simulés, et leurs suppressions concernent uniquement des fichiers temporaires de test.

### Profils d’utilisation

Le bloc **Profils d’utilisation**, au-dessus des identifiants, propose cinq modèles :

| Modèle | Réglages |
| --- | --- |
| **Simple** | Standard, options supplémentaires désactivées, générateur de 32 caractères |
| **Sauvegarde** | Compression, Reed–Solomon, traitement récursif |
| **Transfert en parties** | Parties de 100 Mio, taille personnalisable |
| **Protection renforcée** | Mode paranoïaque, préférence de génération de 64 caractères |
| **Sortie opaque** | Déniabilité, préférence de génération de 64 caractères, découpage désactivé |

Choisir un profil remplit les options sans lancer de traitement. Le choix **Chiffrer/Déchiffrer** est conservé ; au déchiffrement, la suite intérieure reste détectée par le volume. L’application d’un profil désactive la récupération forcée : son activation et sa limite restent des réglages manuels. Si changer la récursivité rend la sélection actuelle invalide, le profil n’est pas appliqué et les réglages précédents sont conservés.

Modifier une option ou les préférences du générateur affiche **Profil modifié**. **Rétablir** remet les réglages enregistrés. Le résumé affiche les options courantes et les caractéristiques de ressources connues au chiffrement : mémoire Argon2 de 64 ou jusqu’à 256 Mio, redondance RS et stockage temporaire. Ce ne sont ni des scores de sécurité ni des prévisions de durée.

Dans **Gérer et échanger les profils** :

- **Créer** enregistre une configuration personnalisée ; **Dupliquer** crée une variante des réglages courants, avec un nom proposé à partir du profil sélectionné.
- **Enregistrer** modifie un profil personnel et permet aussi de le renommer. Les modèles intégrés sont immuables et se personnalisent par duplication.
- L’éditeur permet de régler la compression, le mode paranoïaque, RS, le découpage, la déniabilité, la récursivité et les préférences du générateur. Le mode opaque y désactive le découpage incompatible.
- **Mémoriser un dossier de sortie** ajoute une référence de dossier à ce profil. Le chemin doit être absolu, sans caractères de contrôle, et limité à 4096 octets UTF-8. Il est validé comme dossier par le moteur au lancement de l’opération ; importer une référence ne crée pas ce dossier.
- L’enregistrement applique ensuite les réglages du profil au poste de travail lorsque la sélection le permet. Si la sélection empêche leur application, le profil reste enregistré, l’erreur est affichée et **Rétablir** permet de retenter après adaptation de la sélection.
- **Supprimer le profil** retire le profil personnel de la bibliothèque ; ses réglages courants deviennent manuels et peuvent être enregistrés dans un autre profil.

La bibliothèque personnelle est stockée dans `localStorage`, sous `tasarut-profiles-v1`, avec **100 profils au maximum**. Seuls l’identifiant, le nom et les réglages autorisés sont enregistrés. Mots de passe, mots de passe générés, fichiers-clés, commentaires, sources sélectionnées et demandes d’opération sont exclus. Le dossier de sortie n’est enregistré que si l’option est choisie. Au prochain lancement, les profils sont proposés dans la liste ; le modèle Simple et les options de départ restent sélectionnés jusqu’à un nouveau choix explicite. Aucun traitement ni génération de mot de passe ne démarre à l’application d’un profil.

**Exporter le profil sélectionné** exporte aussi bien un modèle intégré qu’un profil personnel. **Exporter les profils personnels** exporte la bibliothèque personnelle. Les dossiers mémorisés font partie de ces réglages et sont donc inclus dans l’export. **Importer un JSON** ajoute des profils personnels avec de nouveaux identifiants ; les noms en conflit sont suffixés `(2)`, `(3)`, etc. L’import ne remplace pas les profils existants et n’applique pas automatiquement les profils ajoutés.

Les fichiers utilisent le format versionné :

```json
{
  "format": "tasarut-profiles",
  "version": 1,
  "profiles": [
    {
      "name": "Transfert USB",
      "settings": {
        "compress": false,
        "paranoid": false,
        "reedSolomon": false,
        "chunks": true,
        "chunkSizeMiB": 250,
        "deniability": false,
        "recursive": false,
        "generatorLength": 32,
        "generatorSymbols": true
      }
    }
  ]
}
```

`outputDirectory` est un champ facultatif de `settings`. Les autres champs sont obligatoires. La taille maximale est **1 Mio** et chaque document contient de 1 à 100 profils. Les propriétés inconnues, types incorrects, versions non prises en charge, tailles hors limites et combinaisons incompatibles sont refusés avant modification de la bibliothèque. Les échanges de fichiers sont disponibles aussi dans l’aperçu navigateur. Dans Tauri, les dialogues natifs ouvrent/enregistrent le JSON ; la publication du fichier est atomique et un export antérieur choisi dans le dialogue d’enregistrement peut être remplacé.

Une bibliothèque locale illisible n’est ni appliquée ni effacée automatiquement : les modèles intégrés restent accessibles, avec **Réessayer le chargement** ou une **Réinitialisation** explicite. Un échec d’écriture conserve la bibliothèque précédente et laisse l’éditeur ouvert avec les valeurs saisies.

### Raccourcis clavier

Cliquer sur **Raccourcis clavier** dans la barre supérieure, ou appuyer sur **F1**, pour consulter les commandes et leur disponibilité. Les boutons et le champ de mot de passe ont également des infobulles et des attributs `aria-keyshortcuts`. Sur macOS, l’aide affiche **Cmd** à la place de **Ctrl**.

| Raccourci | Action |
| --- | --- |
| **F1** | Afficher l’aide des raccourcis |
| **Ctrl + 1** | Ouvrir l’espace de travail |
| **Ctrl + 2** | Ouvrir les modes avancés |
| **Ctrl + 3** | Ouvrir À propos |
| **Ctrl + O** | Ajouter des fichiers |
| **Ctrl + Maj + O** | Ajouter un dossier et activer le traitement récursif |
| **Ctrl + Maj + K** | Ajouter des fichiers-clés |
| **Ctrl + Maj + S** | Choisir le dossier de sortie |
| **Ctrl + Maj + G** | Ouvrir le générateur de mots de passe |
| **Ctrl + K** | Placer le curseur dans le champ de mot de passe |
| **Ctrl + E** | Choisir Chiffrer |
| **Ctrl + D** | Choisir Déchiffrer |
| **Ctrl + Entrée** | Lancer l’opération avec les validations habituelles |
| **Ctrl + .** | Demander l’annulation du lot actif, même depuis une autre page |
| **Échap** | Fermer l’aide ou le générateur, ou masquer une erreur ; ne pas annuler le traitement |

Les raccourcis d’action s’appliquent à l’espace de travail lorsqu’aucun traitement, sélection ou dialogue natif n’est en cours. Pendant un traitement, la navigation, l’aide et l’annulation restent accessibles. L’aide ne suspend pas le moteur.

Les changements de mode et de page sont ignorés dans les champs de saisie, afin de ne pas modifier le contexte d’une saisie en cours. Les combinaisons explicites pour ajouter des fichiers, ouvrir le générateur, placer le curseur ou lancer l’opération peuvent être utilisées depuis ces champs. La saisie ordinaire, copier/coller, sélectionner tout et annuler une modification conservent leur fonctionnement. Les événements de composition, AltGr et les répétitions automatiques de touches ne déclenchent pas les commandes.

Les dialogues d’aide et de génération isolent leur contenu du reste de l’interface. **Tab / Maj + Tab** restent dans le dialogue ; **Échap** le ferme et restitue le focus, ainsi que la sélection du champ d’origine lorsqu’il existe encore. Les raccourcis d’action ne traversent pas un dialogue. Une réponse tardive du générateur fermé est ignorée et ne réutilise pas l’ancien mot de passe généré.

La rangée numérique physique est reconnue pour **Ctrl + 1/2/3** sur AZERTY. Pour **Ctrl + .**, les claviers nécessitant Maj pour produire le point sont pris en charge. Ces raccourcis sont locaux à la fenêtre de Tasarut ; aucune touche globale du système n’est enregistrée. Dans l’aperçu navigateur, les commandes de fichiers continuent d’expliquer qu’elles nécessitent l’application de bureau.

### Annuler une opération

Pendant un traitement, cliquer sur **Annuler l’opération** dans le panneau de progression. Le bouton affiche **Annulation en cours…** et reste désactivé jusqu’à la fin de la demande. L’application attend l’arrêt du moteur et le nettoyage avant de réactiver les commandes et de vider les champs de mot de passe.

- Le fichier en cours est marqué **Annulé** ; sa sortie temporaire, les volumes intérieurs temporaires et les parties préparées mais non publiées sont supprimés.
- Les fichiers suivants sont marqués **Non traité** et ne sont pas démarrés. Une annulation pendant la préparation initiale peut terminer sans résultats par fichier, avant même le début du lot.
- Les résultats déjà terminés restent conservés. Les sources et les fichiers de sortie préexistants ne sont jamais supprimés ou écrasés.
- Les sous-dossiers créés pour préparer le fichier en cours sont retirés s’ils sont encore vides ; les sous-dossiers préexistants ou contenant un résultat restent en place.
- Une annulation est présentée comme un arrêt demandé, pas comme un échec d’authentification ou une récupération partielle publiée. En mode forcé, un préfixe récupéré du fichier annulé n’est pas conservé.

L’arrêt est **coopératif**, contrôlé entre les blocs, les étapes, les lectures de fichiers-clés et les fichiers du lot. Une dérivation **Argon2** déjà en cours, une opération système de lecture/écriture/synchronisation ou une opération de bibliothèque en cours doit d’abord retourner ; l’interface reste utilisable et affiche l’attente. La fermeture de la fenêtre reste suspendue jusqu’à la fin du nettoyage. L’annulation concerne tous les modes, dont Reed–Solomon, compression, découpage, enveloppe opaque et récupération forcée.

La publication sans écrasement constitue le **point de validation final**. Une demande arrivée juste après cette publication ne retire pas un résultat complet : ce fichier reste terminé et l’arrêt s’applique aux suivants. Si tout était déjà terminé, le lot peut donc finir normalement. Chaque lot a son propre jeton d’annulation et son identifiant ; une demande tardive pour un ancien lot ne peut pas annuler un nouveau lot.

### Mode paranoïaque

Le commutateur se trouve dans **Options des fichiers** au chiffrement. Il applique :

1. **Argon2id v1.3** avec 256 Mio, 6 itérations et 4 voies, sortie de 128 octets.
2. **XChaCha20**, puis **Serpent-256 en mode CTR-128 big-endian**, avec des clés séparées de 32 octets.
3. **HMAC-SHA3-512** avec une troisième clé de 64 octets, sur l’en-tête cryptographique et le contenu chiffré final.

La compression, les fichiers-clés, les commentaires publics et le traitement récursif restent disponibles. Les opérations sont plus lentes et la dérivation utilise 256 Mio par fichier, en plus des buffers. Les fichiers sont traités successivement.

Sans Reed–Solomon, ce mode produit des volumes **v2** et le mode standard continue de produire des volumes **v1** inchangés. Avec Reed–Solomon, ils sont protégés par une enveloppe **v3**. Les anciennes versions ne peuvent pas lire les formats ajoutés après leur publication. Au déchiffrement, chaque format et chaque mode sont détectés automatiquement. L’indication de profil avant déchiffrement est une métadonnée non encore vérifiée.

Une cascade n’est pas une preuve automatique d’un niveau de sécurité supérieur : c’est la construction demandée, avec une spécification et des tests de référence, encore sans audit indépendant.

### Reed–Solomon

Activer **Reed–Solomon** dans **Options des fichiers** avant de chiffrer. Cette option fonctionne avec les deux modes de chiffrement, les fichiers-clés, la compression et le traitement récursif.

- Code systématique **RS(136,128)** : 128 octets conservés tels quels, puis 8 octets de parité.
- Protection du volume complet : en-tête cryptographique, commentaires, contenu chiffré et tag d’authentification.
- Correction d’au plus **4 octets endommagés par bloc de 136 octets**, à positions inconnues, avant vérification du MAC.
- Surcoût : **6,25 % sur les blocs complets**, plus un descripteur protégé de 136 octets et jusqu’à 127 octets de remplissage final. Le pourcentage est plus important pour les petits fichiers.
- Lecture, correction et déchiffrement en flux, sans copie temporaire du volume complet ni chargement intégral en mémoire.
- Au déchiffrement, détection et correction automatiques ; le résultat indique les blocs et octets corrigés pendant la première passe complète.
- Le volume source n’est jamais réécrit. En mode normal, le fichier déchiffré n’est publié qu’après authentification réussie.

Le mode normal traite les substitutions d’octets, pas les insertions, suppressions, décalages ou fichiers tronqués. Au-delà de 4 erreurs dans un bloc, la correction peut échouer ou produire un autre mot de code ; l’authentification cryptographique reste donc indispensable. Reed–Solomon n’authentifie pas les données. Le mode forcé décrit ci-dessous propose une récupération distincte, sans cette garantie.

### Déchiffrement forcé

1. Choisir **Déchiffrer** et sélectionner les volumes endommagés.
2. Activer **Déchiffrement forcé** dans **Options des fichiers**.
3. Saisir le mot de passe et les fichiers-clés habituels. Le mode forcé ne retrouve pas un mot de passe perdu et ne permet pas de vérifier un secret lorsque le MAC est invalide.
4. Régler si nécessaire la **limite de récupération par fichier** : 4096 Mio par défaut, réglable de 1 à 1048576 Mio (1 Tio).
5. Choisir le dossier de sortie puis cliquer sur **Récupérer les fichiers**.

Les sorties sont nommées `nom.extension.recovered` et affichées comme **RÉCUPÉRATION NON AUTHENTIFIÉE**. Un mauvais mot de passe, de mauvais fichiers-clés ou des paramètres cryptographiques abîmés peuvent produire des octets inutilisables. Même si le rapport indique un MAC conforme, ce chemin de récupération ne certifie pas sa sortie comme le chemin normal.

Comportement :

- Fichiers non compressés : conserver les octets disponibles, à la longueur déclarée ou à la limite choisie. La taille déclarée peut elle-même être endommagée ; la sortie n’est pas considérée comme fiable.
- MAC invalide ou tag manquant : continuer explicitement la récupération et l’indiquer dans le rapport.
- Reed–Solomon : corriger les blocs récupérables, conserver les octets de données présents des blocs irrécupérables et en relever les positions. Les positions sont celles du **volume chiffré intérieur**, pas du fichier déchiffré.
- Queue de volume v3 tronquée : conserver les octets encore présents, sans fabriquer du texte chiffré pour la partie absente. Jusqu’à 8 octets de parité finale manquants peuvent être reconstruits comme effacements connus lorsque le code le permet.
- Compression : décompresser un flux Zstandard en suivant exactement sa fin de trame. Si la trame est abîmée ou incomplète, conserver le préfixe déjà produit ; aucune reprise arbitraire après une erreur Zstandard n’est promise.
- Limite : arrêter la production à la taille maximale demandée. La fenêtre de décompression est bornée à 128 Mio et les buffers restent indépendants de la taille totale du volume.
- En-tête critique illisible, version/suite inconnue, aucun octet récupérable d’un fichier non vide, ou erreur de lecture/écriture : refuser la publication plutôt que deviner une clé, un nonce ou un décalage.

Le rapport affiche la quantité récupérée, le caractère partiel, l’état du MAC (conforme, invalide, absent, non vérifié), les corrections RS, les blocs irrécupérables, les octets internes manquants, l’arrêt de décompression et la limite atteinte. Les positions de dommages sont limitées aux 128 premières zones ; le compte total des blocs reste conservé. Le rapport est affiché dans l’interface et retourné par l’API Rust ; aucun fichier de rapport séparé n’est créé.

Le mode forcé est désactivé par défaut et n’est pas enregistré entre les lancements. Passer au chiffrement le désactive. Les sources restent intactes et les sorties existantes ne sont jamais écrasées. Les formats v1/v2/v3 ne changent pas avec cette fonctionnalité.

### Découper en parties

1. Choisir **Chiffrer**, puis activer **Découper en parties** dans **Options des fichiers**, ou utiliser son bouton dans **Modes avancés**.
2. Régler la **taille maximale des parties** : 100 Mio par défaut, de 1 à 1048576 Mio. La limite est de 65536 parties par volume ; la dernière peut être plus petite. Même un petit fichier produit un ensemble avec une seule partie.
3. Lancer le chiffrement. Chaque fichier produit un dossier `nom.extension.tasarut.parts`, contenant `manifest.tasarut` et `000001.part`, `000002.part`, etc. La taille choisie borne chaque fichier `.part` ; le manifeste est séparé.
4. Pour déchiffrer, remettre **toutes les parties et le manifeste dans le même dossier**, puis sélectionner le dossier, son manifeste ou une partie quelconque. Tasarut les regroupe comme un seul volume et réassemble automatiquement. Le dossier peut être renommé ; pour restaurer le nom initial automatiquement, conserver le suffixe `.tasarut.parts`.

Le découpage intervient après le chiffrement et, si activée, après la protection Reed–Solomon. Il fonctionne avec les deux suites, la compression, les fichiers-clés, les commentaires publics et le traitement récursif. Les numéros de parties, leur nombre, les longueurs et leurs empreintes BLAKE2b-512 sont liés au secret du volume par le MAC du manifeste. Les parties manquantes, mélangées, tronquées ou modifiées sont refusées, sans publication de texte clair. Modifier des empreintes publiques ne permet pas de contourner le MAC.

Le dossier complet est préparé temporairement, puis publié par un renommage atomique sans écrasement sur Linux. Une erreur gérée supprime la préparation ; un arrêt brutal peut laisser un dossier temporaire caché. Une collision, même avec un dossier vide ou un lien symbolique, est refusée.

La lecture et le réassemblage se font en flux, avec des buffers de 256 Kio. Cette première version utilise un **volume chiffré temporaire complet** : prévoir environ deux fois sa taille pendant le chiffrement, et sa taille plus la sortie pendant le déchiffrement. L’inspection utilise également un temporaire chiffré dans le dossier temporaire système. Le manifeste reste borné à environ 4 Mio. La dérivation du secret est effectuée pour le manifeste puis pour le volume.

L’enveloppe de parties est vérifiée strictement avant Reed–Solomon et avant la récupération forcée. Une partie endommagée n’est donc pas récupérée par ces modes dans cette version ; un ensemble intact peut utiliser leur fonctionnement normal. Les commentaires restent publics et l’inspection ne vérifie pas le MAC du manifeste ; dans un ensemble découpé, leurs octets sont toutefois inclus dans les empreintes authentifiées au déchiffrement et ne peuvent être changés librement comme dans un volume simple.

### Déniabilité — enveloppe opaque

1. Choisir **Chiffrer**, puis activer **Déniabilité** dans **Options des fichiers**, ou utiliser le bouton de **Modes avancés**. La sélection de ce mode depuis Modes avancés conserve le choix Chiffrer/Déchiffrer en cours.
2. Choisir éventuellement le mode paranoïaque, Reed–Solomon, la compression et des fichiers-clés. L’enveloppe opaque est appliquée **après** ces traitements, sur le volume entier.
3. Chiffrer. La sortie par défaut est `nom.extension.bin` : ni signature `TASARUT`, ni commentaire public, ni profil, ni paramètres KDF, ni taille originale ne sont lisibles dans ses octets. Le fichier peut être renommé sans altérer son contenu.
4. Pour le relire, choisir explicitement **Déchiffrer** et activer **Déniabilité**, puis sélectionner le fichier et fournir le mot de passe et les mêmes fichiers-clés. Il reste une **entrée opaque, pas encore authentifiée**, jusqu’à validation du secret. Il n’est pas identifié comme volume lors de l’ajout et ne peut pas être inspecté sans secret.

L’enveloppe utilise **XChaCha20 + BLAKE2b-512 à clé**, avec un domaine de dérivation distinct et un profil fixe **Argon2id v1.3 : 256 Mio, 6 itérations, 4 voies, 64 octets de sortie**. Ce profil est le même quel que soit le chiffrement intérieur ; aucun essai de paramètres fournis par le fichier n’est effectué. Un sel de 32 octets et un nonce de 24 octets aléatoires constituent son seul préfixe public. L’intégralité du préfixe, la longueur et les données chiffrées sont authentifiées. L’enveloppe est vérifiée avant tout traitement du volume intérieur, puis revérifiée sur une seconde passe avant son utilisation.

Interactions :

- **Commentaires publics** : indisponibles en mode opaque. Le texte saisi dans un autre mode est conservé dans l’interface, mais n’est pas transmis au chiffrement opaque. L’API Rust refuse une demande avec commentaire non vide.
- **Découpage** : indisponible, car son manifeste public révèle un ensemble Tasarut. L’activation de Déniabilité désactive le découpage ; choisir le découpage depuis Modes avancés désactive Déniabilité.
- **Reed–Solomon** : sa structure est chiffrée à l’intérieur. La vérification du MAC extérieur reste obligatoire : une corruption extérieure est refusée avant toute correction RS. Ce mode ne propose donc pas la récupération d’une enveloppe opaque endommagée.
- **Déchiffrement forcé** : incompatible avec ce format. Le mode opaque ne contourne jamais son MAC extérieur. Choisir la récupération forcée depuis Modes avancés désactive Déniabilité.
- **Mode paranoïaque, compression, fichiers-clés et traitement récursif** : disponibles. Le profil intérieur est détecté après authentification de l’enveloppe.

La propriété fournie est une **absence de signature publique reconnaissable dans les octets**, avec une sortie d’apparence aléatoire selon les propriétés des primitives utilisées. Ce n’est pas une construction de chiffrement déniable avec mot de passe leurre ou volume caché. Noms, extensions, taille totale, dates, traces d’utilisation et possession du secret peuvent fournir des indices. Le nom par défaut conserve celui de la source ; l’application n’efface pas ces indices externes. Sans compression, la longueur permet encore des déductions sur la taille originale. Aucun remplissage destiné à cacher les longueurs n’est ajouté.

Cette implémentation lit et écrit en flux, mais utilise un temporaire complet du **volume intérieur chiffré**, dans le dossier de sortie, à permissions restreintes. Prévoir sa taille en plus de la sortie ; les dérivations extérieure et intérieure sont successives. Les fichiers existants ne sont jamais écrasés. Les secrets et buffers privés utilisent `Zeroizing`. Le mode n’est pas enregistré entre lancements.

### Commentaires

Ils ne sont **ni chiffrés ni authentifiés**, par conception. Une personne ayant accès au volume peut les lire, les modifier, les supprimer ou les remplacer. Leur modification n’invalide pas le contenu chiffré, si la structure reste valide. Utiliser seulement une description informative et non sensible, dans un environnement de confiance. La limite est de 64 Kio UTF-8.

Dans un volume v3, ils sont protégés contre la corruption accidentelle, mais restent publics et non authentifiés : leur modification intentionnelle demande simplement de recalculer la parité publique des blocs concernés. Cela ne nécessite ni mot de passe ni fichier-clé. La lecture d’un commentaire ne vérifie pas l’authenticité du volume.

### Traitement et intégrité

- Lecture et écriture en flux, avec des buffers de 256 Kio ; la consommation mémoire ne croît pas avec la taille totale du fichier. Argon2id utilise en plus 64 Mio (standard) ou 256 Mio (paranoïaque), et Zstandard ses propres buffers.
- Un sel de 32 octets et un nonce de 24 octets frais sont générés pour chaque volume.
- Argon2id produit 64 octets en standard (32 XChaCha20, 32 BLAKE2b à clé), ou 128 octets en paranoïaque (32 XChaCha20, 32 Serpent, 64 HMAC-SHA3-512). Le domaine de dérivation est différent pour chaque format.
- L’en-tête cryptographique et l’intégralité du texte chiffré sont authentifiés, à l’exception de la longueur du commentaire et du commentaire.
- Déchiffrement normal en deux passes sur le même fichier : vérification complète, puis déchiffrement et seconde authentification avant publication du résultat. La récupération forcée utilise un chemin distinct à une passe, avec un rapport et une sortie non authentifiée.
- Résultat écrit dans un fichier temporaire à permissions restreintes, puis publié sans écraser de fichier existant. Sur une erreur gérée, le temporaire est supprimé automatiquement. Une interruption brutale du processus peut laisser un temporaire sur le disque.
- En mode normal, la décompression n’est entreprise qu’après la première vérification et sa sortie est bornée par la taille authentifiée. En mode forcé, elle intervient sur un flux non authentifié, avec les bornes de sortie et de fenêtre décrites ci-dessus.
- Les secrets Rust gérés par Tasarut utilisent `Zeroizing` ; le mot de passe de l’interface n’est pas enregistré et ses champs sont vidés après une opération. JavaScript et les copies IPC ne permettent pas de garantir l’effacement de toutes les copies mémoire.
- Les commentaires sont affichés comme du texte, jamais interprétés comme du HTML.
- Les liens symboliques ne sont pas parcourus. Les sous-dossiers de sortie symboliques sont refusés. L’application suppose que les sources et les dossiers de sortie ne sont pas modifiés simultanément par un autre processus ; ce n’est pas une isolation contre un adversaire local.
- La progression est **par octet de l’étape en cours**, avec un compteur séparé des fichiers traités. Le chiffrement compte les octets du fichier source avant compression ; la vérification et le déchiffrement comptent les octets du contenu chiffré logique, après lecture RS éventuelle. Le découpage, le réassemblage et les passes de l’enveloppe opaque ont leurs propres compteurs. Une nouvelle passe repart de zéro avec son libellé : le pourcentage ne représente pas une estimation globale du lot ni du temps restant.
- La dérivation des clés et l’enregistrement du résultat utilisent un indicateur indéterminé. Une récupération compressée affiche les octets consommés sans inventer de total : la fin d’une trame endommagée peut être inconnue. Atteindre 100 % des octets d’une passe ne publie pas un fichier : les vérifications, finitions et écritures nécessaires doivent encore réussir. Les fichiers vides sont gérés sans division par zéro.
- Les événements de progression sont limités à environ 10 par seconde, avec transmission immédiate des changements d’étape, des derniers octets et du résultat. L’interface actualise uniquement le panneau de progression. Une seule opération fonctionne à la fois ; la fermeture de la fenêtre est suspendue pendant le traitement pour lui permettre de terminer.

## Vérification et compilation

```bash
npm run build
cargo test -p tasarut-core -- --test-threads=2
cargo test -p tasarut --lib
cargo check -p tasarut
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
npm run test:ui
```

Les tests du moteur couvrent les fichiers vides, binaires et multi-buffers, la compression, les mauvais mots de passe, les altérations et troncatures, les commentaires modifiables, les fichiers-clés, le refus d’écrasement et le parcours récursif.

Les tests de récupération couvrent les deux suites cryptographiques, les sorties avec MAC invalide, les tags absents, les troncatures, les blocs RS bruts, les parités finales absentes, les préfixes Zstandard, les limites de sortie et le maintien du refus de ces données en mode normal.

Les tests de découpage couvrent les deux suites, Reed–Solomon, la compression, les fichiers vides et multi-buffers, les fichiers-clés, la sélection et la déduplication des ensembles, les parties absentes/mélangées/tronquées, la falsification des empreintes, les manifestes malformés, les liens symboliques, les collisions et le nettoyage des erreurs. Les tests d’interface vérifient aussi la taille choisie, les traductions et sa transmission à Rust.

Les tests d’enveloppe opaque couvrent les profils intérieurs standard/paranoïaque/RS, la compression, les fichiers vides et multi-buffers, les fichiers-clés, l’absence de signature et d’inspection publique, les mauvais secrets, les altérations du sel/nonce/contenu/tag, les troncatures et entrées aléatoires, les collisions, les options incompatibles et le nettoyage. Un vecteur indépendant de `scripts/generate-deniable-vector.py`, produit par **libargon2**, **libsodium** et Python `hashlib`, vérifie le résultat exact de l’enveloppe et sa lecture. Le test d’interface couvre aussi l’activation explicite au déchiffrement et l’exclusion des options incompatibles.

Les tests de progression vérifient les compteurs intermédiaires multi-buffers, la compression, les fichiers vides, les passes de découpage/RS/enveloppe opaque, la récupération limitée et les erreurs d’authentification sans fausse fin réussie. Les tests Tauri vérifient la limitation des événements ; le test d’interface simule les événements de plusieurs passes, les totaux inconnus et les événements d’un ancien lot. Le moteur expose `encrypt_with_progress`, `decrypt_with_progress`, `decrypt_deniable_with_progress` et `force_decrypt_with_progress`, avec un callback `ByteProgress { phase, processed_bytes, total_bytes }`. Les API sans callback restent disponibles.

Les tests d’annulation vérifient l’absence de sortie et de temporaires résiduels pendant les différents traitements, les arrêts avant publication, le déchiffrement compressé avec des données déjà mises en tampon, la suppression du préfixe de récupération forcée et la conservation d’un résultat publié juste avant la demande. Les tests Tauri vérifient le périmètre du jeton, le blocage d’un nouveau lot pendant le nettoyage, l’arrêt des fichiers suivants et le retrait des seuls sous-dossiers nouvellement créés et vides. Les tests d’interface vérifient l’attente, le bouton stable pendant les événements, la distinction des résultats et les réponses IPC tardives.

Les tests de raccourcis vérifient l’aide en trois langues, le focus et la sélection, les dialogues natifs sans ouverture multiple, les protections de saisie/composition/répétition, la validation de lancement, l’aide pendant le traitement, l’annulation depuis une autre page, AZERTY/Cmd et les réponses tardives du générateur.

Les tests de profils couvrent les modèles multilingues, les modifications/rétablissements, la conservation des secrets saisis, la création/renommage/duplication/suppression, la persistance sans secrets, les noms affichés comme texte, les échanges JSON natifs et navigateur, les conflits de noms, les documents invalides/trop grands, les échecs de stockage et les sélections récursives incompatibles. Les tests Tauri vérifient également les échanges atomiques, le schéma strict, les liens symboliques et la transmission exacte des champs `chunkSizeMiB` / `recoveryLimitMiB` de l’interface.

Les tests de suppression vérifient les fichiers reconnus et les originaux conservés, les remplacements entre aperçu et exécution, les parents symboliques, les dossiers avec entrées étrangères, les ensembles complets et interrompus, les fichiers-clés protégés, les liens physiques, la reconnaissance opaque sans temporaire en clair, les résultats TRIM simulés et l’absence de fausse preuve d’effacement. Les tests Tauri contrôlent l’expiration et l’usage unique des jetons. Les tests d’interface vérifient la confirmation, les listes affichées comme texte, l’annulation partielle, le TRIM facultatif et les rapports complets.

La détection de stockage est testée avec un sysfs temporaire simulé : partitions NVMe/SSD/HDD, couches LUKS/LVM sans propagation discard, RAID mixte et dépendances partagées, périphériques virtuels, propriétés absentes ou invalides, topologies tronquées, cycles et limites de parcours. Le contrat JSON natif et l'interface couvrent les états connus/indéterminés, plusieurs systèmes de fichiers, les noms affichés comme texte et les trois langues. Ces tests ne demandent aucun TRIM réel et ne constituent pas une qualification de supports physiques.

Pour intégrer l’annulation dans un autre client Rust, utiliser les variantes `encrypt_with_control`, `decrypt_with_control`, `decrypt_deniable_with_control` ou `force_decrypt_with_control` avec `OperationControl::new(&token, &mut callback)`. `CancellationToken` est clonable ; appeler `cancel()` depuis le thread de l’interface demande l’arrêt. Le moteur retourne `Error::Cancelled` et une phase `ProgressPhase::Cancelled` seulement lorsque l’opération s’arrête effectivement avant sa publication finale. Les anciennes API restent utilisables sans annulation. Le pont Tauri expose `cancel_batch({ id })` ; son booléen indique si la demande a été adressée au lot actif, pas si son dernier fichier a pu être arrêté avant publication.

Des vecteurs déterministes v1/v2 produits indépendamment vérifient aussi le résultat exact du chiffrement et le déchiffrement. Ils utilisent **libargon2**, **libsodium**, **libgcrypt** et Python `hashlib`/`hmac` ; leur générateur est `scripts/generate-vectors.py`. Les tests Rust n’ont pas besoin de ces bibliothèques système. Deux threads limitent les allocations simultanées des tests Argon2id renforcés.

Le vecteur RS provient d’une implémentation polynomiale Python indépendante (`scripts/generate-rs-vector.py`), sans dépendances externes. Les tests vérifient chaque position d’erreur dans un bloc, quatre erreurs simultanées, les limites de blocs, le remplissage final, les en-têtes abîmés, les troncatures et l’authentification après recalcul malveillant de parité.

Les tests Playwright couvrent le changement de langue, le générateur, l’aperçu et l’affichage de commentaires non fiables. Ils utilisent Chrome installé sur Linux (`CHROME_PATH` permet un autre chemin), ou Chromium Playwright après `npx playwright install chromium`. Le dernier test emploie un pont IPC simulé ; il ne remplace pas un essai natif de bout en bout.

Créer les paquets Linux :

```bash
npm run tauri -- build --bundles deb,rpm
```

Ils seront placés dans `target/release/bundle/deb/` et `target/release/bundle/rpm/`. Pour compiler le binaire sans générer de paquet : `npm run tauri -- build --no-bundle`. Une cible AppImage reste disponible avec `--bundles appimage`. Les builds de développement avec `--debug` vont dans `target/debug/bundle/` et ne sont pas destinés aux magasins.

L’icône source est `public/key.svg`. Pour régénérer les icônes de l’application :

```bash
npm run tauri -- icon public/key.svg
```

## Organisation

```text
Tasarut/
├── crates/tasarut-core/  # moteur Rust indépendant de la GUI et tests
├── src/                 # interface, styles et dictionnaires en/fr/kab
├── public/key.svg       # icône source
├── src-tauri/           # commandes IPC, événements et configuration Tauri
├── packaging/linux/     # lanceur et métadonnées AppStream DEB/RPM
├── scripts/             # générateur indépendant des vecteurs de test
└── docs/                # formats, distribution Linux et feuille de route
```

Voir [les formats v1/v2/v3](docs/FORMAT.md), [la distribution Linux](docs/LINUX.md) et [la feuille de route](docs/ROADMAP.md).
