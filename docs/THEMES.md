# Thèmes et paysages de Tasarut

## Choisir son ambiance

Le menu de la barre supérieure permet de changer immédiatement de thème.
La page **Thèmes**, dans la navigation latérale, présente les six ambiances
avec leurs fonds, palettes et descriptions en anglais, français et kabyle.
Le thème sélectionné est indiqué par une bordure, une coche et un libellé.
Les cartes sont accessibles au clavier avec Tab puis Entrée ou Espace.

Le thème **Par défaut** conserve l'identité graphite et menthe de Tasarut.
Un halo discret, des contrastes plus lisibles et des légendes légèrement
agrandies complètent cette base.

| Thème | Paysage illustré | Palette | Verre des panneaux | Flou du fond |
| --- | --- | --- | --- | --- |
| Par défaut | Halo menthe, arcs et lignes discrets | Graphite, menthe | 4 px, saturation 105 %, opacité 96 % | 0 px |
| Désert | Dunes au crépuscule et lumière ambrée | Brun profond, terracotta, ambre | 18 px, saturation 112 %, opacité 87 % | 0,5 px |
| Montagnes de Kabylie | Reliefs inspirés du Djurdjura, cèdres et vallée | Vert forêt, olive, pierre | 12 px, saturation 105 %, opacité 88 % | 0 px |
| Océan | Clair de lune, houle et eaux profondes | Bleu abyssal, turquoise | 22 px, saturation 125 %, opacité 87 % | 1 px |
| Espace | Planète à anneaux, étoiles et nébuleuse | Indigo, violet, lavande | 16 px, saturation 115 %, opacité 86 % | 0 px |
| Pôle Nord | Banquise, iceberg et aurore | Bleu polaire, glace, vert d'eau | 26 px, saturation 95 %, opacité 89 % | 0,7 px |

Chaque ambiance règle aussi la teinte des surfaces, les champs, les boutons,
les bordures, les ombres, les rayons des panneaux et le voile devant le fond.
Les panneaux de dialogue utilisent une surface opaque assortie au thème.
Les avertissements et actions destructrices conservent leurs couleurs
sémantiques chaudes et rouges.

## Disponibilité et préférence locale

Les six fonds sont des **illustrations vectorielles originales**, dans
`public/themes/`. Le paysage de Kabylie propose une évocation dessinée du
Djurdjura. Ces fonds sont inclus dans la compilation
et utilisés depuis l'origine locale ; aucun service d'images ou téléchargement
externe n'est nécessaire.

Seul l'identifiant du thème est enregistré dans `localStorage`, sous
`tasarut-theme-v1`. Au lancement suivant, il est restauré avant le rendu de
l'interface. Une valeur inconnue ou illisible revient au thème par défaut.
Si l'écriture de la préférence échoue, l'ambiance reste applicable pour la
session et la galerie indique que le choix n'a pas pu être mémorisé.

Cette préférence est distincte des profils d'utilisation et des demandes de
chiffrement. Changer de thème préserve les champs et réglages de l'espace de
travail. Pendant une opération, le sélecteur et les cartes sont désactivés.

## Lisibilité et compatibilité

- Les textes et légendes d'un panneau représentatif, les champs et le bouton
  principal sont vérifiés par les tests avec un contraste d'au moins 4,5:1 dans
  chacun des six thèmes ; pour les panneaux
  translucides, le test utilise même un fond blanc comme borne conservatrice.
- Le choix est indiqué autrement que par la couleur et le focus clavier est
  visible. Les mises en page sont vérifiées à 1200, 860 et 480 pixels de large.
- Les fonds restent immobiles. Les transitions respectent
  `prefers-reduced-motion` ; `prefers-reduced-transparency` remplace les surfaces
  vitrées par des surfaces opaques et retire le flou des panneaux.
- Si `backdrop-filter` et sa variante WebKit ne sont pas disponibles, les
  panneaux utilisent une surface opaque de remplacement.

Les captures et tests automatisés sont effectués avec Chromium. Vérifier
aussi le rendu natif WebKitGTK lors de la qualification Fedora/Ubuntu/Mint,
notamment le flou, la charge graphique et les préférences d'accessibilité.

## Organisation du code

- `src/themes.ts` : registre fermé des six identifiants, chargement, sauvegarde
  et application de la préférence ; actualise également la couleur du navigateur.
- `src/themes.css` : palettes, propriétés optiques, surfaces sémantiques,
  galerie et mises en page compactes ; complète `src/style.css`.
- `src/main.ts` : sélecteur, galerie, focus et intégration à l'interface.
- `src/i18n.ts` : noms, descriptions et états en trois langues.
- `public/themes/*.svg` : fonds locaux et aperçus, sans scripts ni ressources externes.
- `tests/themes.spec.ts` : six paysages, captures, contrastes, conservation des
  saisies, persistance, clavier, traductions, préférences système et séparation
  des demandes natives de chiffrement.
