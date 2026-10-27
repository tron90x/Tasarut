# Distribution Linux : Fedora, Ubuntu et Mint

## Cibles

| Environnement | Paquet natif | Diffusion par magasin |
| --- | --- | --- |
| Fedora maintenu | RPM | Dépôt RPM avec métadonnées AppStream, ou Flatpak/Flathub |
| Ubuntu et dérivées (dont Mint) | DEB | Dépôt APT avec métadonnées AppStream, ou Flatpak/Flathub |
| App Center d’Ubuntu | Le DEB reste installable localement | Publication dans le Snap Store via un paquet Snap distinct |

Les familles Linux sont les cibles du projet. Les builds et tests actuels sont exécutés sur Linux Mint 22.3 ; une validation réelle sur Fedora, sous GNOME/Wayland notamment, reste une étape de distribution. Le premier socle Ubuntu/Mint visé est Ubuntu 24.04 / Mint 22 ; les autres versions demandent une vérification des bibliothèques disponibles.

## Générer des paquets

Depuis la racine du projet, avec les prérequis du README :

```bash
npm ci
npm run tauri -- build --bundles rpm,deb,appimage
```

Résultats de production dans `target/release/bundle/` :

- `deb/Tasarut_0.4.0_amd64.deb` pour Ubuntu/Mint x86_64 ;
- `rpm/Tasarut-0.4.0-1.x86_64.rpm` pour Fedora x86_64.
- `appimage/Tasarut_0.4.0_amd64.AppImage` pour les systèmes Linux x86_64
  compatibles avec la base de compilation.

Lancer l'AppImage depuis la racine du projet :

```bash
chmod +x ./target/release/bundle/appimage/Tasarut_0.4.0_amd64.AppImage
./target/release/bundle/appimage/Tasarut_0.4.0_amd64.AppImage
```

Le lancement sans montage FUSE peut utiliser l'option
`--appimage-extract-and-run`. Pour la construction elle-même, la variable
`APPIMAGE_EXTRACT_AND_RUN=1` permet aussi aux outils AppImage de s'exécuter sans
montage FUSE. Le lancement et le rendu ont été vérifiés sur Mint dans ce mode.
Le format n'annule pas les exigences de glibc de la compilation.

L’architecture dépend de la plateforme de compilation. Il ne s’agit pas d’un paquet multiarchitecture. Compiler sur une base compatible avec la plus ancienne distribution ciblée : changer le suffixe DEB en RPM ne change pas les exigences de glibc ni des bibliothèques liées.

Pour valider rapidement des paquets de développement :

```bash
npm run tauri -- build --debug --bundles deb,rpm
```

Ces paquets vont dans `target/debug/bundle/`. Ils sont plus volumineux et ne sont pas les paquets à publier. Pour refaire uniquement le packaging d’un binaire déjà construit :

```bash
npm run tauri -- bundle --debug --bundles deb,rpm
```

Sur cette machine, le gros binaire avec symboles de débogage ralentissait fortement le packaging RPM. Pour vérifier les paquets de développement, le binaire a été allégé avec `strip --strip-debug target/debug/tasarut` avant la commande `bundle`. Cette commande retire les informations de débogage du binaire généré, pas du code source. Le profil de production configure déjà `strip = true` et ne nécessite pas cette étape manuelle.

Installation locale sur la distribution correspondante :

```bash
# Ubuntu / Mint
sudo apt install ./target/release/bundle/deb/Tasarut_0.4.0_amd64.deb

# Fedora
sudo dnf install ./target/release/bundle/rpm/Tasarut-0.4.0-1.x86_64.rpm
```

Tauri ajoute automatiquement les dépendances DEB WebKitGTK 4.1 / GTK 3. La
compilation de production sur Mint 22.3 utilise des symboles de **glibc 2.39** :
le DEB déclare `libc6 (>= 2.39)` et le RPM la capacité
`libc.so.6(GLIBC_2.39)(64bit)`. La configuration RPM déclare aussi
`webkit2gtk4.1` et `gtk3` et utilise Zstandard niveau 3 pour éviter une compression
de paquet excessive pendant les builds de développement. Node.js et Cargo ne
sont pas requis chez les utilisateurs du paquet compilé. Vérifier le minimum
glibc à nouveau si la plateforme de compilation change.

Le mode révocable v4 nécessite en plus un TPM2 physique accessible et le paquet
`tpm2-tools`, sans swap persistant actif. Tasarut contrôle la disponibilité des
outils, l'accès au périphérique et le swap ; l'origine physique du TPM reste à
établir sur le banc. L'installation du DEB/RPM ne qualifie pas le matériel. Exécuter la
[procédure de qualification TPM](TPM-QUALIFICATION.md) avec le paquet et le
compte utilisateur réellement ciblés, et conserver un compte rendu par
configuration Fedora/Ubuntu/Mint.

Pour valider la détection préalable du stockage de la suppression renforcée,
ouvrir son aperçu sur des volumes de test placés sur les supports ciblés
(NVMe, SATA, USB, LUKS/LVM et RAID, selon la configuration). Comparer les
périphériques et propriétés déclarés avec une observation indépendante :

```bash
lsblk -o NAME,TYPE,ROTA,TRAN,DISC-MAX,MOUNTPOINTS
```

Le type indiqué repose sur les propriétés du noyau, pas sur une preuve du
matériel physique. Vérifier particulièrement les SSD sous LUKS sans discard :
la nature non rotative et l'absence de discard effectif doivent être affichées
séparément. Btrfs, tmpfs, overlay et les stockages sans topologie fiable peuvent
rester indéterminés. La détection ne demande aucun TRIM ; sa prise en charge
réelle et les permissions sont évaluées uniquement si l'utilisateur le demande.

## Lanceur et présentation dans les magasins

Les paquets incluent :

- le binaire `/usr/bin/tasarut` ;
- le lanceur `/usr/share/applications/Tasarut.desktop`, basé sur `packaging/linux/tasarut.desktop` ;
- les icônes `tasarut.png` en 32, 64, 128, 256 HiDPI et 512 pixels dans le thème hicolor, ainsi que `tasarut.svg` dans sa variante scalable ;
- les métadonnées `/usr/share/metainfo/app.tasarut.desktop.metainfo.xml`.

Le lanceur et les résumés AppStream ont des traductions anglais/français/kabyle. Le lanceur ne déclare pas encore une association de fichier : le programme n’a pas de traitement des arguments `%f` pour ouvrir un volume au double-clic.

Le lanceur utilise `Icon=tasarut` et `StartupWMClass=Tasarut`, correspondant à
la classe de fenêtre observée sous Mint/X11. La première image PNG de la
configuration Tauri est `icons/128x128@2x.png` (256 × 256) : c'est aussi l'icône native
embarquée de la fenêtre, utilisable lors d'un lancement direct du binaire.
Les petites images restent disponibles pour les menus, et le SVG pour les
tailles adaptées par le thème d'icônes.

Sur la machine Mint/X11 de validation, GTK publie correctement l'icône de
fenêtre de 256 pixels, mais ignore celle de 512 pixels dans `_NET_WM_ICON`.
Le format 512 reste installé pour le thème d'icônes ; il n'est pas utilisé
comme image native de la fenêtre.

Si un paquet corrigé garde la même version `0.4.0`, le réinstaller explicitement
sur Mint/Ubuntu pour remplacer la version déjà installée :

```bash
sudo apt install --reinstall ./target/release/bundle/deb/Tasarut_0.4.0_amd64.deb
```

Fermer puis rouvrir Tasarut après la réinstallation. Un raccourci épinglé
conservant une ancienne association peut être retiré puis épinglé à nouveau.

Vérifier ces fichiers :

```bash
desktop-file-validate packaging/linux/tasarut.desktop
appstreamcli validate --no-net packaging/linux/app.tasarut.desktop.metainfo.xml
```

Le fichier AppStream actuel est une base de développement. Le validateur signale l’**URL de projet manquante** et les **informations de développeur manquantes**, car aucune URL publique ni identité de publication n’a encore été fournie. Ajouter les vraies valeurs, les captures d’écran hébergées et les liens de suivi au moment de préparer la publication. Aucun domaine ou compte fictif n’est utilisé.

## Magasins

**Flatpak local** : un premier paquet de test est disponible avec
`scripts/build-flatpak-local.py`, GNOME Platform 51 et les portails. Il utilise
`org.example.Tasarut`, branche `local`, pour cohabiter avec le DEB. Les essais
natifs Mint couvrent le lancement, un aller-retour de chiffrement par portail,
un retrait contrôlé sans TRIM et la persistance du thème. Voir
[FLATPAK.md](FLATPAK.md) pour les commandes et les limites matérielles.

**Flathub** est accessible depuis GNOME Software sur Fedora et le gestionnaire
de logiciels de Mint, ainsi que sur Ubuntu après configuration de Flatpak et
d'une interface compatible. La soumission reste à préparer : identifiant
d'éditeur réel, métadonnées complètes, compilation des sources dans le SDK,
dépendances hors ligne, qualification et manifeste conforme aux règles
actuelles. Aucun dépôt ni pull request de soumission Flathub n'est créé par
le packaging local.

**Le Snap Store / App Center d’Ubuntu** demande un paquet Snap séparé et son intégration des accès aux fichiers. Un paquet DEB ne peut pas être envoyé comme tel au Snap Store.

**Les dépôts natifs APT/RPM** nécessitent leurs propres étapes d’hébergement, de signature et d’intégration AppStream. Déposer un DEB/RPM local ne rend pas automatiquement l’application disponible dans les magasins.

La licence déclarée dans les métadonnées du projet est GPL-3.0-or-later. La feuille de route prévoit de confirmer ce choix et d’ajouter le texte de licence avant diffusion.
