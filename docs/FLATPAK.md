# Flatpak local de Tasarut

## Première étape : un paquet installable pour les essais

Le profil local utilise l'identifiant réservé **`org.example.Tasarut`** et la
branche **`local`**. Son lanceur s'appelle **Tasarut (Flatpak local)**, pour
cohabiter avec le DEB installé. Cet identifiant ne revendique aucun domaine
ni éditeur et devra être remplacé avant une publication officielle.

Ce premier paquet **reconditionne le binaire de production existant**, avec ses
thèmes et son interface intégrés. Les bibliothèques sont résolues et contrôlées
dans **`org.gnome.Platform/x86_64/51`**. Il ne s'agit pas encore d'une compilation
des sources avec le SDK dans un environnement de construction Flatpak.

## Construire et installer

Prérequis : Python 3, Flatpak, `desktop-file-validate`, le runtime GNOME 51
installé et un binaire de production Linux **x86_64** à
`target/release/tasarut`. Le script ne télécharge pas de SDK et n'a pas besoin
de `flatpak-builder` pour ce reconditionnement local.

Si le runtime n'est pas présent, l'installer depuis Flathub :

```bash
flatpak install flathub org.gnome.Platform//51
```

Depuis la racine du projet, produire le paquet et l'installer pour le compte
utilisateur, sans remplacer le DEB :

```bash
python3 scripts/build-flatpak-local.py --install
```

Le script utilise une zone de préparation temporaire qui lui appartient,
contrôle les bibliothèques avec `ldd` dans le runtime, exporte un dépôt local
et publie le fichier final après réussite. Les anciennes préférences de
l'application Flatpak sont conservées lors d'une réinstallation.

Résultats dans `target/flatpak/` :

- `Tasarut_0.4.0_x86_64.flatpak` : paquet local installable ;
- `repo/` : dépôt OSTree local, branche `local` ;
- `SHA256SUMS` : empreinte du paquet ;
- `BUILD-INFO.json` : version, runtime, empreintes et méthode de construction ;
- `flatpak-metadata.txt` : permissions et commande du paquet ;
- `runtime-libraries.txt` : contrôle des bibliothèques dans le runtime.

La version du nom de fichier est prise dans la configuration Tauri.

Pour installer le fichier sur une autre machine disposant du runtime :

```bash
flatpak install --user ./target/flatpak/Tasarut_0.4.0_x86_64.flatpak
flatpak run --user org.example.Tasarut
```

Pour remplacer une installation locale existante, ajouter `--reinstall` à la
commande d'installation. Pour vérifier le paquet, depuis `target/flatpak/` :

```bash
sha256sum -c SHA256SUMS
```

## Permissions et fichiers

Le paquet dispose de Wayland, du repli X11, de l'IPC nécessaire à X11 et de
`dri` pour le rendu graphique. Le réseau est désactivé. Il ne demande aucun
accès statique `home`/`host`, aucun `--device=all`, aucun lancement sur l'hôte
et aucun accès global aux bus D-Bus.

`GTK_USE_PORTAL=1` active le sélecteur natif par les portails. Les fichiers et
dossiers choisis sont accessibles à l'application avec les droits accordés
par le portail. Pour produire des résultats, sélectionner explicitement un
dossier de sortie. Pour une suppression renforcée, sélectionner le **dossier
contenant les volumes** via Ajouter un dossier permet d'accorder l'accès au
parent nécessaire au renommage et au retrait contrôlés ; une autorisation de
lecture portant sur un seul fichier ne garantit pas ces droits.

Dans le confinement testé, les chemins accordés passent par
`/run/flatpak/doc/…`. La détection du disque peut rester **indéterminée**, car
ces chemins correspondent au système de fichiers FUSE du portail.

## Fonctions matérielles

- **TPM** : les nœuds TPM ne sont pas exposés par ce profil et les outils
  `tpm2-tools` de l'hôte ne sont pas fournis. Le mode révocable reste donc
  indisponible avec ses permissions par défaut. Aucun coffre logiciel ou
  secret de remplacement n'est ajouté.
- **TRIM** : aucune permission administrative supplémentaire n'est accordée.
  La demande peut être refusée par le portail, le système de fichiers ou le
  noyau. Aucun TRIM réel n'a été demandé pendant les essais locaux.
- **Suppression** : l'aperçu et le retrait contrôlé restent distincts de TRIM
  et de la révocation TPM. Un échec de permissions reste un échec rapporté,
  sans déclaration d'effacement physique.

## Vérifications effectuées sur Mint

Avec Flatpak 1.14.6 et GNOME Platform 51, en X11 :

- Installation utilisateur du fichier `.flatpak` réussie ;
- bibliothèques de l'application résolues dans le runtime ;
- lancement natif, interface et fond local affichés ;
- identité de fenêtre `org.example.Tasarut` / `Org.example.Tasarut`, cohérente
  avec le lanceur exporté ;
- chiffrement d'un fichier de test de 304128 octets, sélectionné par le portail ;
- déchiffrement par le portail vers un autre dossier : octets identiques à la
  source, original conservé ;
- aperçu de suppression d'un volume de test puis retrait confirmé via un
  dossier accordé par le portail : volume retiré, original et sortie déchiffrée
  conservés, aucune demande TRIM ;
- changement vers le thème Pôle Nord, rendu examiné et préférence conservée
  après arrêt et relancement ;
- fichier du projet hôte inaccessible sans sélection, nœuds TPM absents du
  confinement, absence de permissions générales fichiers/périphériques/réseau.

La compilation actualisée avec Threefish-1024 a également été testée dans
l'interface Flatpak : choix de l'algorithme, source et sorties par portails,
publication v5 suite 1 vérifiée, puis déchiffrement automatique dans une
nouvelle instance avec comparaison octet par octet conforme.

Ces contrôles utilisent des fichiers temporaires de test. Le rendu et les
fonctions restent à qualifier sur Fedora/Wayland, Ubuntu et d'autres portails.
La navigation des lecteurs d'écran dans la vue WebKit n'a pas été qualifiée :
le pont AT-SPI du processus WebKit n'était pas joignable par le pilote de test.
Les essais natifs ont utilisé les raccourcis et les sélecteurs GTK de l'hôte.

Le validateur AppStream signale encore l'absence d'URL publique et
d'informations de développeur. Ces champs restent à remplir avec les vraies
informations de publication ; aucune identité ou URL fictive n'est ajoutée.

## Préparer une future publication

La publication Flathub reste une étape séparée, avec :

1. Un identifiant d'éditeur réel et des métadonnées complètes, une licence
   finalisée, un dépôt public et une version stable ;
2. une compilation des sources dans un SDK maintenu, dépendances Cargo/npm
   préparées pour les builds hors ligne et licences des composants installées ;
3. la qualification des portails et des fonctions annoncées ;
4. un manifeste et une soumission conformes aux règles de Flathub.

Ce script et les métadonnées locales sont assistés par IA. Ce sont des outils
de test local, sans manifeste de soumission Flathub. Les règles actuelles de
Flathub imposent la déclaration des parties générées par IA, interdisent les
manifestes générés/assistés par IA et l'automatisation des soumissions ou des
échanges de revue par des agents. Le manifeste de soumission et ces échanges
devront être réalisés humainement.

Voir les [exigences Flathub](https://docs.flathub.org/docs/for-app-authors/requirements)
et la [procédure de soumission](https://docs.flathub.org/docs/for-app-authors/submission).
