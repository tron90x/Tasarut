# Qualification des volumes révocables sur TPM physique

## État et portée

Cette procédure accompagne le format v4 et le fournisseur `tpm2-tools`. Elle est
**à exécuter** : les tests mémoire et les échanges TPM simulés du projet ne sont
pas une qualification matérielle. Aucun résultat matériel n'est consigné ici.

La qualification porte sur une combinaison précise : version de Tasarut,
distribution, noyau, version de `tpm2-tools`, modèle/firmware du TPM et réglages
du système. Répéter sur les configurations Fedora, Ubuntu et Mint destinées à
être prises en charge ; un succès sur une machine ne valide pas les autres.

Le format et ses hypothèses sont décrits dans [FORMAT.md](FORMAT.md) ; les
parcours utilisateur dans le [README](../README.md#volumes-révocables-tpm2--v4).
Cette procédure vérifie le comportement observable. Elle ne prouve pas
l'absence de copies de secrets en mémoire, ni la résistance interne du TPM.

## 1. Préparer le banc et relever son état

Utiliser un TPM2 physique dont l'état ne peut pas être restauré avec un
instantané de VM, et des fichiers de test sans données personnelles. Relever
son origine dans la documentation de la machine : la présence de `/dev/tpmrm0`
et la détection « TPM 2.0 » ne suffisent pas à établir cette propriété.

Les essais de saturation, de perte d'accès pendant une opération et d'arrêt
brutal demandent un banc dédié : ils peuvent laisser des index orphelins.
Conserver un inventaire des index de test ; la plage `0x015a0000–0x015affff`
n'est pas, à elle seule, une preuve qu'un index appartient à cette campagne.
Ne pas réinitialiser le TPM ou supprimer des index préexistants pour préparer
le banc. Cela peut rendre illisibles des volumes et affecter d'autres usages.

Installer les outils sur la distribution concernée :

```bash
# Ubuntu / Mint
sudo apt install tpm2-tools

# Fedora
sudo dnf install tpm2-tools
```

Exécuter Tasarut et les commandes d'observation avec le **même compte utilisateur**.
Configurer l'accès au périphérique selon la distribution ; un test effectué
uniquement avec `sudo` ne valide pas les droits de ce compte. Tasarut cherche
les sept outils `tpm2_nvdefine`, `tpm2_nvwrite`, `tpm2_nvwritelock`, `tpm2_nvread`,
`tpm2_nvreadpublic`, `tpm2_nvundefine` et `tpm2_getcap` dans les chemins système.
Leurs cibles doivent appartenir à root et ne pas être modifiables par le groupe
ou les autres utilisateurs.

Relever la version de Tasarut et l'identifiant de sa révision ou l'empreinte du
binaire testé. Ces commandes ne lisent que des informations système et TPM
publiques ; adapter le périphérique à celui affiché dans Tasarut :

```bash
uname -r
tpm2_getcap --version
swapon --show
tpm2_getcap -T device:/dev/tpmrm0 properties-fixed
tpm2_getcap -T device:/dev/tpmrm0 properties-variable
tpm2_getcap -T device:/dev/tpmrm0 handles-nv
```

Si Tasarut choisit `/dev/tpm0`, remplacer `/dev/tpmrm0` par `/dev/tpm0` dans toutes
les commandes. Conserver l'inventaire initial `handles-nv`. Relever la
distribution et sa version, le fabricant et le firmware TPM, le type de swap,
et si l'autorisation de la hiérarchie propriétaire est vide ou non vide, **sans
consigner sa valeur**.

Le banc nominal doit être sans swap persistant actif. Le zram n'est accepté que
sans stockage de secours (`backing_dev` égal à `none`). Tasarut ne change pas
cette configuration ; vérifier de nouveau après chaque redémarrage. Ne pas
utiliser l'hibernation comme substitut au redémarrage dans ces essais.

Dans l'application native, choisir **Volume révocable TPM**, puis **Vérifier le
TPM**. Noter le périphérique et l'état affichés. « Dépendances TPM détectées »
ne confirme pas encore les droits de création, l'autorisation propriétaire ou
la capacité NV : ils sont contrôlés lors des opérations.

## 2. Création, lecture et combinaisons de formats

Préparer un fichier vide, un petit fichier texte et un fichier binaire de plus
de 256 Kio. Pour les essais d'annulation, prévoir aussi un fichier assez grand
pour que l'étape de chiffrement soit observable. Garder les sources et réserver
un dossier de sortie distinct à chaque essai.

Exécuter les huit combinaisons du tableau sur le fichier binaire :

| Cas | Suite | Compression | Reed–Solomon |
| --- | --- | --- | --- |
| F1 | Standard | Non | Non |
| F2 | Standard | Oui | Non |
| F3 | Standard | Non | Oui |
| F4 | Standard | Oui | Oui |
| F5 | Paranoïaque | Non | Non |
| F6 | Paranoïaque | Oui | Non |
| F7 | Paranoïaque | Non | Oui |
| F8 | Paranoïaque | Oui | Oui |

Pour chaque cas :

1. Activer le mode révocable, saisir/confirmer un mot de passe de test et
   renseigner l'autorisation propriétaire si le banc en utilise une.
2. Chiffrer ; vérifier la publication d'un seul volume `.tasarut.rev` et la
   conservation de la source. Choisir **Déchiffrer**, sélectionner ce volume
   et ressaisir le mot de passe (les champs sont vidés après une opération).
   Ouvrir l'aperçu de révocation pour relever l'identifiant et l'index, puis
   fermer **sans confirmer**.
3. Examiner uniquement les métadonnées publiques de l'index. Remplacer l'index
   d'exemple ci-dessous par celui relevé, sans lire le contenu secret NV :

   ```bash
   tpm2_nvreadpublic -T device:/dev/tpmrm0 0x015a1234
   ```

4. Attendre une taille de **64 octets**, SHA-256 (`0x000b`), les attributs
   exactement `0x22042804` et une politique d'autorisation vide. Ce masque est
   `AUTHWRITE | WRITEDEFINE | AUTHREAD | NO_DA | WRITTEN | WRITELOCKED`.
   Des droits OWNERREAD/OWNERWRITE ou d'autres attributs sont un échec.
5. Déchiffrer vers un dossier neuf et comparer les octets source/sortie, par
   exemple avec `cmp -- "chemin/source" "chemin/sortie"` (code de sortie 0).
6. Répéter le déchiffrement avec un mauvais mot de passe : aucune sortie claire
   ne doit être publiée ; l'index et le volume restent présents. Revenir au bon
   mot de passe et vérifier que le volume reste lisible.

Répéter F1 pour les fichiers vide et texte, puis avec deux fichiers-clés :
lecture réussie avec leur contenu et leur ordre initiaux ; refus avec un
fichier absent, un contenu changé ou l'ordre inversé. L'autorisation
propriétaire n'est pas nécessaire à la lecture d'un volume existant : vérifier
ce point sur un banc à autorisation propriétaire non vide en laissant ce champ
vide au déchiffrement.

Garder au moins deux volumes indépendants lisibles pour les essais suivants.
Noter leurs index distincts. Une copie du même fichier chiffré, en revanche,
doit garder le même identifiant et le même index.

## 3. Persistance après redémarrage et révocation des copies

1. Copier un volume valide sur un support de sauvegarde ; comparer ses octets
   avec l'original et noter l'identifiant/index. Garder un second volume
   indépendant comme témoin.
2. Fermer Tasarut, redémarrer normalement la machine et vérifier les prérequis,
   notamment le swap. Relire les attributs publics : le verrou `WRITELOCKED`
   doit persister. Déchiffrer le volume, sa copie et le témoin vers des dossiers
   neufs ; tous doivent correspondre à leurs sources.
3. Ajouter **une seule** copie du premier volume dans Tasarut. Saisir les bons
   secrets, ouvrir **Révoquer les clés des volumes sélectionnés**, contrôler
   chemin/identifiant/index, puis confirmer.
4. Attendre un résultat **révocation confirmée**. Dans la réponse native,
   cela correspond à `revoked: true`, `hardwareAbsenceConfirmed: true`, sans
   erreur. Le fichier chiffré doit rester présent et inchangé.
5. Refaire `tpm2_nvreadpublic` pour cet index : attendre un refus indiquant un
   handle absent, pas une erreur de transport ou de permissions. Conserver le
   code de retour et la sortie publique pour distinguer ces situations.
6. Tenter de déchiffrer toutes ses copies, puis restaurer les octets sauvegardés
   dans un nouvel emplacement et retenter. Avec les bons secrets, aucune ne
   doit produire de sortie. Le volume témoin doit toujours se déchiffrer.
7. Redémarrer de nouveau, refaire les contrôles d'absence et les tentatives de
   lecture, puis vérifier encore le témoin. La restauration du seul fichier
   chiffré ne doit pas rétablir le secret TPM supprimé.

Ne pas sélectionner plusieurs copies d'un même volume en attendant plusieurs
succès de révocation : la première supprime leur index commun ; les suivantes
rencontrent un index absent. Cet état ne doit pas être annoncé comme une
nouvelle révocation confirmée.

## 4. Autorisations et protection de la confirmation

Sur un volume de test encore lisible, utiliser un nouvel aperçu pour chaque
tentative, car le jeton est consommé à l'exécution :

| Essai | Résultat attendu |
| --- | --- |
| Fermer l'aperçu sans confirmer | Index inchangé, volume toujours lisible |
| Confirmer avec un mauvais mot de passe ou de mauvais fichiers-clés | Révocation non confirmée, index intact, lecture correcte toujours possible |
| Confirmer avec une mauvaise autorisation propriétaire | Révocation non confirmée, index intact ; les bons secrets de lecture fonctionnent toujours |
| Modifier/remplacer le fichier après l'aperçu, avant confirmation | Refus `source_changed`, index intact |
| Attendre plus de dix minutes avant confirmation | Aperçu expiré, aucun index retiré ; préparer un nouvel aperçu |
| Corrompre le contenu d'une copie v4 sans RS, puis préparer et confirmer un nouvel aperçu | MAC refusé, index intact, original toujours lisible |
| Redemander une révocation après suppression de l'index | Absence signalée, aucun nouveau succès de révocation |

Pour la corruption, modifier un octet du contenu chiffré d'une **copie sans RS**,
après l'en-tête de 126 octets et avant le tag final de 64 octets. Un volume RS
peut corriger cette modification et n'est pas adapté à cet essai de refus.

Tester également une création avec une mauvaise autorisation propriétaire :
aucun volume ne doit être publié et l'inventaire NV doit rester inchangé.
Limiter les tentatives erronées sur la hiérarchie propriétaire selon la
politique du banc ; `NO_DA` sur l'index n'exempte pas toutes les autorisations
TPM des protections contre les essais répétés. Utiliser une configuration
déjà provisionnée à autorisation non vide pour tester ce cas, sans changer
l'autorisation d'un TPM en service pour cette campagne.

## 5. Indisponibilité et changement de machine

Exécuter ces essais sur une configuration dédiée, puis revenir à l'état nominal :

Consigner avant l'essai la méthode de retrait/restauration des droits ou du
périphérique propre au banc, ainsi que l'étape visée. Une modification des
droits du nœud ne ferme pas nécessairement un descripteur déjà ouvert : si
l'accès n'a pas réellement été perdu pendant l'opération, classer cette
injection comme non concluante et relever l'étape effectivement atteinte.

- **Périphérique sans droits pour le compte de test** : Vérifier le TPM doit
  signaler un accès refusé ; aucune opération v4 ne doit réussir.
- **Outils absents** : un banc sans le paquet doit signaler les dépendances
  manquantes. Réinstaller le paquet normal avant de reprendre les essais.
- **Swap persistant actif** : le mode doit être bloqué. Une fois le banc
  configuré sans swap persistant, refaire la vérification avant de traiter.
- **Autre machine physique équipée d'un autre TPM** : copier un volume de test
  non révoqué et tenter sa lecture avec les bons mot de passe/fichiers-clés.
  Attendre un refus, sans sortie claire et sans création d'index sur cette
  seconde machine. Une collision numérique d'index ne doit pas suffire à
  lire le volume.
- **Accès perdu pendant une révocation** : ne pas annoncer de confirmation si
  l'absence n'a pas pu être vérifiée. Après restauration de l'accès, contrôler
  l'index explicitement : le retrait peut déjà avoir eu lieu. Classer le résultat
  initial comme non confirmé, pas comme preuve que la clé a été conservée.

Une réinitialisation/perte réelle du TPM n'est pas nécessaire pour le parcours
nominal. Si cette propriété est testée sur un banc sacrifiable distinct,
documenter séparément les étapes de l'administrateur et les données détruites.

## 6. Annulation, erreurs et nettoyage

Relever `handles-nv` avant et après chaque essai ; inspecter aussi le dossier de
sortie, y compris ses fichiers cachés :

1. Annuler pendant le chiffrement d'un grand fichier, après la phase de
   stockage TPM mais avant publication. Attendre la fin du nettoyage. Il ne
   doit rester ni résultat incomplet ni nouvel index, sauf erreur de nettoyage
   explicitement rapportée avec son numéro d'index.
2. Créer une collision de nom de sortie, puis tenter le chiffrement : la sortie
   préexistante doit rester identique et aucun index supplémentaire ne doit
   persister après l'échec géré.
3. Révoquer un lot de volumes indépendants, puis annuler. Les révocations
   terminées restent effectives, les suivants sont non traités ; une commande
   matérielle mutante déjà engagée peut terminer. Confronter chaque résultat à
   la présence réelle de son index, sans exiger une interruption instantanée.
4. Sur le banc dédié, interrompre brutalement le processus pendant une
   création. Au redémarrage, rechercher les index nouveaux et temporaires
   chiffrés : un orphelin est possible et n'est pas une révocation réussie.

Conserver tout `revocable_cleanup_failed:0x…` dans le compte rendu. Le retrait
administrateur d'un orphelin doit viser uniquement un index attribué à la
campagne par l'inventaire avant/après et les observations de l'opération.
Ne pas nettoyer toute la plage Tasarut indistinctement. Ne pas exporter le
record NV secret pour établir cette attribution.

## 7. Capacité NV sur banc dédié

Fixer dans le compte rendu un plafond de créations (par exemple **32**) avant
de commencer. Créer séquentiellement de petits volumes indépendants, en
conservant pour chacun son fichier, ses secrets de test et son index. Arrêter
au premier refus de capacité ou au plafond ; ne pas lancer une boucle illimitée.

- Si l'espace s'épuise, attendre `revocable_tpm_capacity`, sans volume annoncé
  comme publié pour la tentative échouée. Comparer l'inventaire NV avant/après
  cette tentative et contrôler tous les volumes précédemment publiés.
- Révoquer un volume de test, puis tenter une nouvelle création ; vérifier que
  la capacité libérée est utilisable et que les autres volumes restent lisibles.
- Si le plafond est atteint sans saturation, noter **saturation non atteinte** :
  ce résultat ne valide pas le chemin d'épuisement de capacité.

Révoquer ensuite les volumes créés pour l'essai. Un refus NV lié à la cadence
d'écriture ou un timeout n'est pas une preuve de saturation ; conserver son
diagnostic et le classer séparément.

## 8. Compte rendu et clôture

Pour chaque scénario, choisir **réussi**, **échoué**, **non exécuté** ou
**non concluant**. Un scénario omis ou une panne de transport ne devient pas
un succès par déduction à partir des tests simulés. Les champs secrets ne
doivent apparaître ni dans les commandes enregistrées ni dans le rapport.

Modèle à remplir dans un fichier séparé pour chaque configuration :

```text
Date / opérateur :
Version Tasarut / révision ou empreinte du binaire :
Distribution / version / noyau :
Version tpm2-tools :
Modèle de machine / origine physique du TPM :
Fabricant / modèle / firmware TPM :
Périphérique / compte de test / configuration des droits :
Swap et backing zram avant/après redémarrages :
Autorisation propriétaire : vide / non vide (aucune valeur)
Inventaire initial des index NV :
Plafond de créations pour la capacité :

Scénario :
Réglages et taille de la source :
Chemins de test / identifiant public / index NV :
Étapes réellement effectuées :
Résultat attendu / résultat observé :
Statut : réussi / échoué / non exécuté / non concluant
Comparaison source-sortie / présence des fichiers :
Attributs NV ou erreur d'absence, codes de retour :
Résultat Tasarut et erreur éventuelle :
Pièces jointes publiques / captures sans secrets :

Inventaire final / index de test restants / explication :
Nettoyage effectué / orphelins à traiter :
Scénarios non exécutés et restrictions de qualification :
Conclusion pour cette configuration :
```

Avant clôture, révoquer les index de test encore utilisables **via leurs
volumes**, vérifier l'absence de chaque index retiré et comparer l'inventaire
final à l'initial. Les originaux en clair et les sorties déjà déchiffrées sont
distincts : la révocation ne les retire pas.

Joindre les résultats réels avant de cocher la qualification matérielle dans
la [feuille de route](ROADMAP.md). Un banc sans scénario de saturation, sans
autorisation propriétaire non vide ou sans second TPM conserve ces limitations
dans sa conclusion ; ne pas annoncer une qualification complète de ces cas.
