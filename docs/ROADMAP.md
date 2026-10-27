# Feuille de route

## 0.1 — socle fonctionnel

- [x] Tauri 2, moteur Rust indépendant, icône de clé.
- [x] Interface anglais/français/kabyle en alphabet latin.
- [x] Six thèmes persistants avec fonds locaux, palettes et verre adaptés : défaut, désert, Kabylie, océan, espace et pôle Nord.
- [x] Un volume par fichier, XChaCha20 + BLAKE2b à clé, Argon2id.
- [x] Générateur de mots de passe et fichiers-clés.
- [x] Commentaires publics, ni chiffrés ni authentifiés.
- [x] Compression Zstandard et traitement récursif.
- [x] Vérification d’intégrité, sorties temporaires et absence d’écrasement.

## Stabilisation

- [ ] Relecture linguistique kabyle et choix du vocabulaire avec un locuteur.
- [x] Vecteurs déterministes v1/v2 issus de bibliothèques indépendantes.
- [ ] Revue indépendante des formats et du code.
- [ ] Fuzzing du parseur, des fichiers tronqués et des flux compressés.
- [x] Choix Threefish-1024 complet (80 tours), CTR128BE et HMAC-SHA3-512 : v5, v4 suite 3, profils et interface trilingue, vecteurs indépendants et compatibilité des transports.
- [x] Progression par octet de l’étape, passes distinctes et événements limités pour tous les modes.
- [x] Annulation coopérative par lot, nettoyage des temporaires et conservation des résultats terminés.
- [x] Raccourcis clavier, aide F1 anglais/français/kabyle, isolation des dialogues et restauration du focus.
- [x] Profils d’utilisation, cinq modèles, bibliothèque personnelle locale, résumés de ressources et échanges JSON versionnés.
- [x] Suppression renforcée des volumes : aperçu exact, retrait contrôlé, compte rendu et TRIM facultatif des blocs libres sous Linux.
- [x] Détection préalable du stockage par système de fichiers sélectionné : NVMe, SSD/flash ou HDD déclarés, mixte/indéterminé, dépendances LUKS/LVM/RAID et capacité discard effective.
- [x] Volumes v4 révocables, secrets TPM2 NV indépendants, chiffrement direct et absence d’un coffre logiciel sur disque.
- [x] Révocation authentifiée, contrôle des attributs/verrous NV, confirmation d’absence et rapports par volume.
- [x] Procédure reproductible de qualification TPM physique et modèle de compte rendu : [TPM-QUALIFICATION.md](TPM-QUALIFICATION.md).
- [ ] Qualification sur TPM physique, redémarrages, saturation NV, pertes d’accès et autorisations de hiérarchie ; joindre les comptes rendus réels.
- [x] Configuration des paquets Linux DEB/RPM et intégration AppStream.
- [ ] Tests natifs sur Fedora GNOME/Wayland et les versions Ubuntu/Mint ciblées.
- [x] Premier Flatpak local x86_64, runtime GNOME 51, portails, installation utilisateur et essais natifs de chiffrement/déchiffrement, retrait contrôlé sans TRIM et persistance du thème sur Mint/X11.
- [ ] Publication Linux : Flatpak/Flathub, Snap ou dépôts natifs selon le canal choisi.
- [ ] Choix et ajout du texte de licence avant diffusion (métadonnées actuelles : GPL-3.0-or-later).

## Format avancé

### Mode paranoïaque

- [x] Cascade **XChaCha20 → Serpent-256-CTR128BE**, clés indépendantes, IV Serpent distinct.
- [x] Authentification **HMAC-SHA3-512**, tag de 64 octets, en-tête et contenu chiffré authentifiés.
- [x] Profil Argon2id renforcé : **256 Mio / 6 itérations / 4 voies**, sortie de 128 octets.
- [x] Format v2, lecture v1 conservée et détection automatique du profil.
- [x] Interface anglais/français/kabyle, compression, fichiers-clés et traitement récursif compatibles.
- [x] Vecteurs indépendants et tests de corruption, mauvais secrets, continuité du flux et commentaires publics.
- [ ] Mesures de temps et mémoire sur les différentes machines Fedora/Ubuntu/Mint ciblées.

Une cascade n’est pas automatiquement une preuve de meilleure sécurité ; sa construction doit être revue.

### Reed–Solomon

- [x] Code **RS(136,128)** sur GF(256), polynôme 0x11d, 128 octets de données et 8 de parité.
- [x] Enveloppe v3, descripteur protégé, volume complet et padding final défini.
- [x] Correction d’au plus 4 substitutions d’octets par bloc, avant authentification.
- [x] Lecture/écriture en flux et lecture v1/v2 conservée, avec les deux suites cryptographiques.
- [x] Interface anglais/français/kabyle, détection automatique et affichage des corrections.
- [x] Vecteur polynomial indépendant, erreurs à toutes les positions, quatre erreurs, troncatures et refus d’un MAC invalide malgré une parité valide.
- [ ] Support d’effacements dont les positions sont connues, si un futur format les fournit.

### Déchiffrement forcé

- [x] Flux de récupération distinct, toujours **non authentifié**, sorties `.recovered`.
- [x] Récupération des octets disponibles et rapports de blocs irrécupérables, troncatures et intervalles endommagés bornés.
- [x] États du MAC distincts, sans convertir la récupération forcée en authentification réussie.
- [x] Récupération du préfixe Zstandard déjà produit, fin de trame suivie précisément, limites de sortie et de fenêtre.
- [x] Support v1/v2/v3, des deux suites cryptographiques et des fichiers-clés ; sources conservées et collisions refusées.
- [x] Interface anglais/français/kabyle avec activation explicite et présentation distincte des résultats.

### Découpage en parties

- [x] Séparer le volume chiffré en parties de taille choisie.
- [x] Spécifier nommage, ordre, nombre de parties, longueur et liaison authentifiée au volume.
- [x] Réassembler en flux et détecter une partie absente, mélangée ou modifiée.
- [x] Refuser les collisions sans laisser un ensemble partiellement publié ambigu.
- [x] Interface anglais/français/kabyle, sélection automatique d’un ensemble et compatibilité des profils v1/v2/v3.
- [ ] Remplacer le volume chiffré temporaire complet par un lecteur multi-parties seekable et un écrivain directement découpé.
- [ ] Récupération des parties endommagées avec Reed–Solomon ou récupération forcée, avec garanties et rapports spécifiques.

### Déniabilité

- [x] Format d’enveloppe opaque distinct, sans magic ou métadonnées publiques reconnaissables ; reconnaissance explicite nécessitant le secret.
- [x] Profil KDF extérieur fixe : Argon2id 256 Mio / 6 itérations / 4 voies, domaine distinct, aucun paramètre fourni par le fichier.
- [x] Commentaires publics et manifeste de découpage incompatibles, contrôles Rust et interface.
- [x] Reed–Solomon chiffré sous l’enveloppe ; MAC extérieur obligatoire, aucune récupération de corruption extérieure.
- [x] Noms `.bin`, renommage libre et limites des indices externes/longueurs documentés ; aucun volume leurre ou caché.
- [x] Vérification en deux passes, publication sans écrasement, interface anglais/français/kabyle et tests avec vecteur indépendant.
- [ ] Réduire le stockage temporaire du volume intérieur et mesurer temps/mémoire sur les machines ciblées.

Une apparence aléatoire n’autorise pas à promettre que personne ne pourra prouver l’existence d’un volume. Les garanties seront limitées aux propriétés réellement établies du format.
