# KEYCONV — conversion automatique des clés égyptiennes sauvegardées

État 14/10/2026 : branche de recherche, pas encore validée physiquement
sur la nouvelle automatisation. Jeu principal et sauvegardes inchangés.

## Acquis vérifiés sur le vrai iPad

- Une nouvelle récompense Egypt devient +1 000 coins au lieu d'une clé
  lorsque les cinq portes de ce monde sont déjà ouvertes (11/10).
- Une ancienne clé Egypt sauvegardée est devenue 1 000 coins sur un
  profil choisi manuellement avant chargement du guest (12–13/10).
- Persistance et absence de double crédit confirmées au redémarrage.
- Quatre SIGKILL de transaction RTON **synthétique** sur vrai iPad :
  rollback OLD_OLD pour primaire, fallback, committed.tmp ; état
  NEW_NEW préservé si le marqueur final committed était publié.
- Progression réelle confirmée ensuite : 0 clé et 10 010 coins.
- Les SIGKILL ne démontrent PAS la durabilité lors d'une coupure de courant.

## Nouveau mécanisme préparé

Branche `research/keyconv-auto-batch` :
- `world_key_auto_batch.hpp` : preview EN MÉMOIRE de tous les profils,
  ID natif vérifié via local_profiles, jusqu'à 16 profils, quantité
  de clés 1 à 99, pièces des 2 RTON conservées séparément.
- `world_key_auto_settlement.hpp` : traitement séquentiel de chaque
  profil éligible par le même journal transactionnel SHA-256 individuel
  déjà testé. Pas de nouveau format de journal risqué. Préconditions :
  guest arrêté, sauvegarde prélaunch vérifiée, journal précédent
  récupéré proprement, activation volontaire en recherche.
- Si le profil A a été définitivement crédité puis l'app interrompue
  pendant le profil B : A reste converti, B est restauré, la conversion
  de B attend un prochain lancement *propre*. A ne peut pas être
  crédité une deuxième fois.
- Tests C++20 stricts Linux/macOS : 1, 2, 3 et 99 clés,
  plusieurs profils, porte fermée, registre contradictoire, stocks
  divergents, wallet overflow, champs et mondes étrangers préservés,
  double redémarrage et interruption du second profil.
- KEYOBS garde son ancien dialogue manuel en l'absence d'un fichier
  d'activation. Seule la présence du fichier Documents racine
  `PvZ2AutoKeyconvRequest.txt` contenant EXACTEMENT
  `ENABLE_EGYPT_AUTOMATIC_KEYCONV_RESEARCH_V1` suivie d'un saut
  de ligne déclenche la conversion automatique avant le guest.
  Le fichier est lu sans suivi de symlink, limité à 128 octets.
- Le nouveau build de recherche exige un marqueur CI distinct
  `platform/ios/.auto-keyconv-build-request`. L'application reste
  `com.puissantsy.pvz2forios.keyobs` et conserve son sandbox existant.
  La branche de production `main` et le correctif boutique v170
  restent strictement inchangés.

## Limites importantes

- Conversion du stock ancien : uniquement Egypt, cinq événements W=2,
  E={13,23,33,39,41}, tous présents une seule fois et état S>=3 dans
  les deux images. Clés qui peuvent encore servir à ouvrir une porte :
  jamais supprimées. Absence de clé : no-op.
- Pirate/Cowboy ont leurs IDs de portes documentés dans les ressources,
  mais leurs états de porte et la migration sauvegarde n'ont pas encore
  une validation iPad équivalente. Ne PAS activer sans preuve.
- Future et Dark sont non activés. Aucun achat premium ou droit
  ancien EA ne doit être modifié par KEYCONV.
- En cas d'erreur, priorité aux sauvegardes et au journal : pas
  d'auto-réparation destructrice.
- La première migration automatique doit être testée UNIQUEMENT avec
  une copie jetable d'une sauvegarde Égyptienne non convertie, et
  seulement après backup extérieur vérifié. Le vrai profil 10 010
  pièces ne doit jamais être restauré ni écrasé pour ce test.

## Protocole iPad une fois l'IPA prête

1. Installer la future IPA au-dessus de KEYOBS (pas de suppression ni
   de reset du dossier Documents ou du laboratoire 4/4).
2. Sans fichier d'activation, vérifier que le comportement KEYOBS
   d'origine et le jeu complet fonctionnent.
3. Préparer dans PvZ2RestoreInbox une **copie jetable** v165 d'une
   ancienne sauvegarde égyptienne non convertie. Vérifier le backup
   externe avant toute restauration. Ne jamais utiliser le profil
   personnel actuel comme fixture.
4. Dans Documents racine de PvZ2 Keys Research, copier le fichier
   d'activation depuis `tools/PvZ2AutoKeyconvRequest.txt` ; fermer et
   relancer l'app.
5. Choisir Restaurer pour la copie jetable si demandée. Le système
   crée un snapshot prélaunch, détecte les clés éligibles et les convertit
   sans demander le choix du profil. Inspecter le log KEYCONV AUTO et
   les compteurs pièces/clés/portes dans le jeu.
6. Hard stop, relance sans restauration, vérifier montant identique et
   zéro double paiement. Tester ensuite plusieurs clés/profils sur
   une copie de sauvegarde uniquement si un fixture adéquat existe.
7. Effacer le fichier d'activation pour revenir au comportement manuel.

**IMPORTANT** : ces étapes sont des critères d'acceptation à venir,
pas des tests déjà effectués. La vraie interface automatique et son
intégration finale dans PvZ2 principal seront considérées validées
seulement APRÈS preuve iPad sur la version auto de KEYOBS.

Après la clôture de KEYCONV, la priorité choisie par l'utilisateur est
la performance en combat avec beaucoup de plantes/projectiles/zombies,
en particulier aux vitesses x1.5 et x2.

## Première IPA automatique KEYOBS — build unique du 14 octobre 2026

**Compilation iPadOS arm64 SUCCESS** : [GitHub Actions #38555269276](https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38555269276), commit exact `2b311afabb8f06aa0cc70cc15ace8e6c19f16722`. L'artefact `PvZ2forIOS-KeyAuto-unsigned` est disponible (ID GitHub `11890551010`) et contient l'IPA non signée et son fichier `.ipa.sha256`. Le digest `sha256:fbc5fca8b751f76c80933eeee9cb1b139ebe2a6d6f788fdd427fda9d90ca68ac` correspond **à l'archive d'artefact GitHub**, pas nécessairement aux octets de l'IPA intérieure. Vérifier le hash intérieur via le fichier fourni si besoin.

Le log de build confirme `** BUILD SUCCEEDED **`, l'identité compilée `CFBundleIdentifier=com.puissantsy.pvz2forios.keyobs`, l'affichage `PvZ2 Keys Research` et les marqueurs `PVZ2KeyconvResearchBuild=1` et `PVZ2KeyconvOriginalIdentifier=com.puissantsy.pvz2forios.keyobs`. Aucune erreur de compilation. Les **4 jobs sans IPA** Linux/macOS/Apple sont verts : [#38555122869](https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38555122869).

**Statut : build prêt, AUTOMATISATION NON ENCORE VALIDÉE SUR LE VRAI IPAD.** Installer seulement comme mise à jour du KEYOBS de recherche, sans désinstaller ni effacer son conteneur et son audit de laboratoire 4/4. Le fichier d'activation `tools/PvZ2AutoKeyconvRequest.txt` doit être copié explicitement dans la racine Documents de KEYOBS sur une **sauvegarde jetable et non convertie**. Ne JAMAIS restaurer la sauvegarde utilisateur 10 010 pièces pour obtenir artificiellement une clé. Au lancement, sans le fichier, comportement manuel précédent inchangé ; avec le fichier et backup vérifié, tous les profils Egypt éligibles sont convertis avant le moteur. Vérifier le nombre exact de clés/pièces et un second démarrage sans crédit supplémentaire. La suite de l'intégration production n'intervient qu'après cette validation.

## Diagnostic iPad du 14 octobre — migration réussie puis restauration inattendue

Nouvel essai sur **véridique iPad** avec IPA automatique #38555269276,
sur une sauvegarde de test présentant cinq portes Égypte ouvertes et une
clé restante. Le journal utilisateur fourni
(`pvz2forios-probe(20261014-124240).log`) prouve :

```text
[KEYOBS SAVE] prelaunch VERIFIED snapshot=...
[KEYCONV AUTO] completed=YES profiles=1 keys=1 coinsDelta=1000 scope=EGYPT_ONLY
[V130 LAUNCHER] Enabling JIT with StikDebug…
# session suivante : le menu v165 propose une restauration.
[KEYOBS RESTORE] verified snapshot restored into isolated app
[KEYOBS SAVE] prelaunch VERIFIED snapshot=...
[KEYCONV PRELAUNCH] FAIL_CLOSED; guest launch prohibited
```

**Acquis :** la demande d'automatisation était valide et la transaction
de la première clé a terminé avec succès **avant le redémarrage JIT**.
L'utilisateur a ensuite effectivement restauré une copie via le prompt
v165, remplaçant la sauvegarde que KEYCONV venait de migrer. La session
suivante a refusé la conversion, mais le code d'origine masquait **la
cause interne exacte** (il attrapait toute exception et l'appelait
« sauvegarde non vérifiée »). Le dump ne prouve donc PAS quel champ précis
de la sauvegarde restaurée est incompatible. Le jeu n'a pas pu atteindre
le premier frame après ce deuxième lancement. Il ne faut PAS déclarer
l'automatisation physiquement validée dans ce scénario.

**Correctifs groupés en recherche (sans toucher à main) :**

1. Avant une migration automatique, **attendre le runtime importé et le
   JIT/StikDebug disponible**, car l'ancienne exécution créditait la clé
   juste avant un redémarrage provoqué par l'attachement JIT.
   Journaliser `awaiting_JIT no_writes=YES` ou
   `awaiting_runtime_import no_writes=YES`.
2. Différencier toute erreur de prévisualisation **RTON en mémoire,
   avant journal** (`ReadOnlyPreviewError`) d'une erreur de fichiers ou
   transaction effective. Seules les erreurs de prévisualisation
   strictement sans écriture offrent le choix explicite
   **« Lancer SANS convertir » / « Rester bloqué »**. Les erreurs après
   début de transaction conservent l'arrêt fail-closed et la récupération.
   Journaliser un code stable non personnel (ex. `KEY_STOCKS_DIVERGE`,
   `GATE_STATES_DIVERGE`, `SLOT_COUNT`, `RTON_PREVIEW_UNSUPPORTED`),
   jamais de noms/profils/RTON ni chemins complets.
3. Renforcer le texte du prompt v165 : lors d'un redémarrage JIT après
   une conversion, **choisir « Ignorer »** pour ne pas restaurer l'ancien
   solde et les anciennes clés.
4. Corriger le statut trompeur « sauvegarde non vérifiée » en
   « démarrage protégé après erreur ».
5. Tester synthétiquement les refus pré-écriture, les portes divergentes,
   les journaux déjà présents (toujours bloquants) et une interruption
   après installation partielle (rollback obligatoire).

Tous les tests sans IPA, y compris compilation iPadOS arm64, sont verts :
[Actions #38567597827](https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38567597827).

**Contournement dans l'ancienne IPA** : déplacer
`PvZ2AutoKeyconvRequest.txt` hors de la racine Documents de KEYOBS,
relancer puis choisir « Ignorer » pour ne ni restaurer ni convertir.
Préserver en particulier le backup externe, `PvZ2Backups` et les
données utilisateur. Ne pas remplacer la progression personnelle de
10 010 coins.

**Étape physique suivante** : un seul build de la version corrigée,
puis tester le parcours JIT avant écriture + auto-conversion après
initialisation sur une **copie jetable**. Ne pas prétendre que le
précédent résultat démontre la persistance au lancement du jeu.
