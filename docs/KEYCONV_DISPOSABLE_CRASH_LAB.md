# KEYCONV — laboratoire de crash jetable sur iPad

**État au 13 octobre 2026 :** code de recherche préparé ; ne pas confondre avec
la conversion native + persistance **déjà validées sur le véritable iPad**.
Le laboratoire SIGKILL/iPadOS reste à tester physiquement.

## Objectif et périmètre

Les tests Linux et macOS prouvent déjà la récupération après des SIGKILL
réels à 15 points de transaction et pendant un rollback. Sur iPad, on
veut vérifier la récupération APFS **sans jamais charger une vraie sauvegarde
dans le laboratoire**.

- Vraies données du jeu : `Library/Application Support/PvZ2forIOS/UserData/No_Backup`.
- Données du laboratoire : `Library/Application Support/.pvz2-keyconv-disposable-lab/UserData/No_Backup`.
- Le laboratoire refuse les chemins dont **n'importe quel ancêtre**
  s'appelle `PvZ2forIOS`, `UserData` ou `No_Backup`.
- Deux RTON synthétiques, profil fictif : 9 010 pièces dans le primaire,
  7 750 dans le fallback, 1 clé Égypte et cinq portes ouvertes.
- Marqueur `LAB_SYNTHETIC_RTON_V1_ONLY` et empreintes SHA-256 obligatoires.
- Journal `lab-audit.log` borné, append-only et fsync ; seules des
  étiquettes de phase et des résultats de récupération y sont écrits.
  Il survit au reset du journal FULLLOAD et aux SIGKILL.
- Les sauvegardes personnelles `pp.dat` et `snapshot2.dat` ne sont jamais
  recopiées ni modifiées par cette fonction.

## Accès volontaire depuis l'app KEYOBS

**Un démarrage normal n'affiche rien et ne déclenche jamais de crash.**

Quand une IPA de recherche contenant ce laboratoire sera prête :

1. Copier [PvZ2CrashLabRequest.txt](../tools/PvZ2CrashLabRequest.txt)
   dans le **dossier Documents racine** visible via
   Fichiers → Sur mon iPad → PvZ2 Keys Research.
   Conserver le nom et le contenu exacts, sans l'insérer dans PvZ2RestoreInbox.
2. Fermer complètement et rouvrir l'app. Le programme récupère d'abord
   un éventuel journal **factice** puis recherche ce fichier de demande.
   Un fichier manquant, altéré, trop gros ou symbolique est refusé.
3. Choisir explicitement `Préparer et choisir un crash factice` ou
   `Ignorer — lancer le jeu`. La préparation crée uniquement de
   nouveaux RTON synthétiques dans le répertoire frère.
4. Choisir **un** checkpoint : après l'écriture du primaire factice,
   après le fallback factice, après `committed.tmp` ou après
   publication du marqueur `committed`.
5. Le second dialogue avertit de la fermeture brutale et exige
   exactement la phrase `JE CONFIRME LE CRASH FACTICE`.
   Annuler ou mal saisir la phrase interdit le SIGKILL.
6. L'app est **censée se fermer instantanément** après ce choix,
   seulement si le guest/JNI/V128 est encore arrêté.
7. Rouvrir l'app. Le laboratoire récupère son journal avant les
   éventuelles restaurations du jeu ; choisir ensuite
   `Voir et copier le rapport factice` pour récupérer les traces
   synthétiques. Un laboratoire existant n'est jamais écrasé.
8. Retirer le fichier de demande pour revenir au lancement habituel.

Résultats attendus : **old-old** après un crash avant le commit,
**new-new** après publication du commit ; aucune récompense ni
altération du profil PvZ2 réel.

## Protections et limites

- Compilation et marqueur de bundle **réservés à l'application KEYOBS**.
- Demande externe exacte + menu de préparation + sélection de phase +
  seconde confirmation textuelle.
- Vérification de guest arrêté ; jamais de SIGKILL au démarrage ou
  pendant le moteur actif.
- Les RTON sources sont tous construits en dur, avec noms/profils fictifs.
- Le journal SHA-256 effectue une récupération avant toute nouvelle
  transaction ; aucun second crédit n'est autorisé.
- Un laboratoire cassé ne débloque aucun accès aux sauvegardes réelles ;
  son audit est conservé pour diagnostic.
- **SIGKILL ≠ coupure d'alimentation :** ce protocole ne prouve pas la
  résistance à une vraie perte d'énergie durant un fsync APFS.
  Ne pas éteindre l'iPad brutalement pendant cet essai.

Les tests CI : `tests/staging/test_keyconv_disposable_crash_lab.cpp`,
`tests/staging/test_world_key_prelaunch_process_kill.cpp`, validations
ObjC++ et compilation arm64 via `verify-world-keys.yml`. Ne produire
qu'une **unique IPA de recherche** après tous les contrôles verts.
L'IPA actuellement fonctionnelle reste conservée intacte.

## Build de recherche unique du 13 octobre 2026

- **IPA compilée avec succès** : [GitHub Actions #38359627207](https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38359627207).
- Commit exact du build : `ac83cbcf28524095a532a00f81a587ad79e82361`.
- Artefact : `PvZ2forIOS-JIT-Probe-unsigned`, identifiant GitHub `11793343950`, archive ZIP avec IPA non signée et SHA-256.
- `BUILD SUCCEEDED` confirmé par le log, plist inspecté : `CFBundleIdentifier=com.puissantsy.pvz2forios.keyobs`, `PVZ2KeyconvResearchBuild=true`.
- Test complet sans IPA prérequis : [CI #38359330455](https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38359330455), trois jobs verts.
- Le fichier d'activation à copier sur iPad est aussi fourni via la conversation ChatGPT sous le nom `PvZ2CrashLabRequest.txt` avec les 38 octets exacts attendus.
- **Aucune validation physique du laboratoire n'a encore eu lieu.** Ne jamais supprimer/remplacer la précédente IPA KEYOBS fonctionnelle ni utiliser la vraie progression pour les tests.

**Test progressif demandé sur iPad :** installer/signer la nouvelle IPA *de recherche*, la lancer **sans** fichier d'activation et confirmer que le jeu fonctionne comme avant. Le test SIGKILL est **optionnel et volontaire** : seulement après vérification des sauvegardes et après copie explicite du fichier d'activation, deux confirmations et saisie de la phrase. La fermeture brutale qui suivra doit être considérée comme prévue. Au redémarrage, choisir `Voir et copier le rapport factice`, puis vérifier que la vraie progression n'a pas changé.

## Premier vrai test iPad — rollback du primaire (PASS)

Le 14 octobre 2026, l'utilisateur a exécuté volontairement le scénario « Après pp.dat factice » sur iPad, puis redémarré et copié l'audit exact :

```text
PREPARED_ONLY_SYNTHETIC
USER_CONFIRMED_SYNTHETIC_CRASH
ARM_PRIMARY_RENAMED
RECOVERY_ROLLED_BACK
VERIFIED_OLD_OLD
```

**PASS sur vrai iPadOS pour ce scénario :** la reprise du journal a effectué un rollback et les deux fichiers RTON synthétiques ont été vérifiés dans leur état initial. `ARM_PRIMARY_RENAMED` est l'étiquette du checkpoint demandé, écrite avant l'injection ; la preuve du résultat de reprise se trouve dans `RECOVERY_ROLLED_BACK` et `VERIFIED_OLD_OLD`. Les sauvegardes réelles du jeu ne figurent pas dans ce laboratoire. Ce test n'est pas une panne d'alimentation.

**Limitation de l'IPA testée :** le répertoire synthétique est volontairement conservé après récupération et la commande `Prepare` refuse de le remplacer. Ne pas demander à l'utilisateur de lancer les trois autres scénarios avec la même IPA ni de supprimer son application ou ses données pour recommencer. Un futur réarmement devra vérifier l'état `OLD_OLD`, conserver l'audit et ne pas toucher aux vraies sauvegardes, avant un seul nouveau build soigneusement testé.

## Réarmement sûr du laboratoire existant

Le premier test sur iPad a été validé avec les cinq lignes d'audit : `PREPARED_ONLY_SYNTHETIC`, `USER_CONFIRMED_SYNTHETIC_CRASH`, `ARM_PRIMARY_RENAMED`, `RECOVERY_ROLLED_BACK`, `VERIFIED_OLD_OLD`.

Le laboratoire ne supprime ni ses RTON synthétiques ni son historique après récupération. Une nouvelle méthode `PrepareOrRearm` permet donc de reprendre la **même expérience** seulement si les deux RTON sont exactement égaux à leurs originaux synthétiques (`OLD_OLD`), le journal actif et `.done` sont absents, le marqueur et le registre factices sont intacts, et l'audit commence par `PREPARED_ONLY_SYNTHETIC`, contient `RECOVERY_ROLLED_BACK` et se termine par `VERIFIED_OLD_OLD`. Le réarmement ajoute uniquement `REARMED_VERIFIED_OLD_OLD` à l'audit ; aucune donnée préexistante du jeu ou du laboratoire n'est supprimée.

Le nouveau bouton s'appelle **Préparer / reprendre le laboratoire factice**. S'il reste un journal incohérent ou si le résultat est déjà `NEW_NEW`, il refuse l'opération, sans réparation forcée. Les tests CI enchaînent les quatre étapes et vérifient la conservation des anciennes lignes.

Après la future installation de l'IPA intégrant ce réarmement, **dans la même application KEYOBS sans désinstallation ni effacement de données** : garder le fichier de demande à la racine de Documents ; choisir successivement `Après snapshot2.dat factice`, puis `Après committed.tmp factice`, et **en dernier** `Après commit publié`. Pour chaque choix : confirmer la phrase, constater la fermeture attendue, rouvrir, lire/copier l'audit complet, vérifier la progression du jeu inchangée. Résultat attendu : `RECOVERY_ROLLED_BACK` + `VERIFIED_OLD_OLD` pour les deux premières étapes ; `RECOVERY_COMMITTED` + `VERIFIED_NEW_NEW` pour la dernière. Aucun redémarrage ne doit doubler un crédit du vrai jeu.

Cette version du laboratoire reste distincte de la validation antérieure de la conversion automatique et ne prouve pas la durabilité lors d'une coupure d'alimentation iPad.


## IPA de réarmement — build complet du 14 octobre 2026

**Compilation iPadOS arm64 complète : SUCCESS**, [GitHub Actions #38534051726](https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38534051726). Commit binaire exact `e870a4f2d1c1bbc0905b8abb286216b3bc35e76d`, artefact `PvZ2forIOS-JIT-Probe-unsigned` (GitHub artifact ID `11879052145`, ZIP contenant IPA non signée + somme SHA256), créé une seule fois après CI native/Apple/Dynarmic entièrement verte [#38533846060](https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38533846060). Les nouveaux tests du laboratoire couvrent **83 assertions** sur chacune des plateformes Linux et macOS, y compris la séquence complète des quatre SIGKILL sur la même copie factice, audit conservé et refus du réarmement après commit. Les anciens **209 tests** de reprise par processus distinct restent verts. Dynarmic historique inchangé.

**Plan iPad :** signer et installer en **mise à jour** de KEYOBS, **sans désinstaller ni nettoyer Documents ou Application Support**. Conserver l'ancienne IPA et les sauvegardes de sécurité à part. Garder `PvZ2CrashLabRequest.txt` à la racine de Documents. Au redémarrage, la récupération du laboratoire se fait avant le jeu ; choisir le bouton **Préparer / reprendre le laboratoire factice**, puis **Après snapshot2.dat factice**. Saisir la même phrase explicite, accepter le SIGKILL, redémarrer puis partager le rapport complet. Résultat attendu pour ce deuxième test : ligne `REARMED_VERIFIED_OLD_OLD`, ligne `ARM_FALLBACK_RENAMED`, puis `RECOVERY_ROLLED_BACK` et `VERIFIED_OLD_OLD`. Ne pas faire `Après commit publié` avant les scénarios non committés : celui-ci produit `NEW_NEW` et verrouille la réutilisation.

**Limite :** aucun test sur le vrai iPad avec cette nouvelle IPA n'a encore été réalisé ; les validations de construction/CI ne prouvent pas la reprise iPad de la nouvelle branche. Signer avec la même méthode et identité pour conserver la sandbox. Si l'outil propose de supprimer KEYOBS pour installer la mise à jour, **ne pas accepter** : cela effacerait le laboratoire et ses preuves. Le test de coupure d'alimentation/APFS reste hors champ.


## Deuxième vrai test iPad — fallback et réarmement (PASS)

Le 14 octobre 2026, l'utilisateur a installé en mise à jour l'IPA avec réarmement
[Actions #38534051726](https://github.com/Puissantsy/PvZ2forIOS/actions/runs/38534051726)
et exécuté le **deuxième** test d'interruption volontaire : **Après snapshot2.dat factice**.
Le rapport transmis directement dans le chat est reproduit intégralement ci-dessous :

```text
PREPARED_ONLY_SYNTHETIC
USER_CONFIRMED_SYNTHETIC_CRASH
ARM_PRIMARY_RENAMED
RECOVERY_ROLLED_BACK
VERIFIED_OLD_OLD
RECOVERY_NO_JOURNAL
VERIFIED_OLD_OLD
RECOVERY_NO_JOURNAL
VERIFIED_OLD_OLD
RECOVERY_NO_JOURNAL
VERIFIED_OLD_OLD
RECOVERY_NO_JOURNAL
VERIFIED_OLD_OLD
RECOVERY_NO_JOURNAL
VERIFIED_OLD_OLD
REARMED_VERIFIED_OLD_OLD
USER_CONFIRMED_SYNTHETIC_CRASH
ARM_FALLBACK_RENAMED
RECOVERY_ROLLED_BACK
VERIFIED_OLD_OLD
```

**PASS sur vrai iPad** : le laboratoire existant a été réarmé **sans
effacement de son ancien historique**, a enregistré la demande du
checkpoint fallback, puis au lancement suivant a exécuté
`RECOVERY_ROLLED_BACK` et vérifié les deux RTON factices en
`VERIFIED_OLD_OLD`. Les cinq paires intermédiaires
`RECOVERY_NO_JOURNAL` / `VERIFIED_OLD_OLD` correspondent à des
récupérations sans journal actif ; ce n'est ni une erreur ni un double crédit.
L'étiquette `ARM_FALLBACK_RENAMED` précède le SIGKILL ; l'état vérifié
à la reprise fournit la preuve de restauration cohérente.

**Statut d'acceptation physique : 2/4 checkpoints PASS.** Il reste
`Après committed.tmp factice` (rollback `OLD_OLD` attendu) puis
`Après commit publié` (commit `NEW_NEW` attendu), à exécuter en
dernier car le laboratoire refusera ensuite tout réarmement.
Aucun nouveau build n'est nécessaire pour ces deux tests dans
l'IPA déjà installée. Le comportement du vrai jeu (clés/pièces) n'est
pas mesuré par ce rapport synthétique ; conserver la sauvegarde réelle
et confirmer séparément son état si nécessaire.

Ces deux scénarios confirment des interruptions de processus et ne
simulent pas une panne matérielle ou une perte d'alimentation pendant
un `fsync` APFS.

## Troisième vrai test iPad — committed.tmp sans commit publié (PASS)

Le 14 octobre 2026, sur la même IPA de laboratoire réarmable et sans effacement des fichiers précédents, l'utilisateur a déclenché le scénario **« Après committed.tmp factice »**, puis relancé l'application. L'audit complet reçu était :

```text
PREPARED_ONLY_SYNTHETIC
USER_CONFIRMED_SYNTHETIC_CRASH
ARM_PRIMARY_RENAMED
RECOVERY_ROLLED_BACK
VERIFIED_OLD_OLD
RECOVERY_NO_JOURNAL
VERIFIED_OLD_OLD
RECOVERY_NO_JOURNAL
VERIFIED_OLD_OLD
RECOVERY_NO_JOURNAL
VERIFIED_OLD_OLD
RECOVERY_NO_JOURNAL
VERIFIED_OLD_OLD
RECOVERY_NO_JOURNAL
VERIFIED_OLD_OLD
RECOVERY_NO_JOURNAL
VERIFIED_OLD_OLD
REARMED_VERIFIED_OLD_OLD
USER_CONFIRMED_SYNTHETIC_CRASH
ARM_FALLBACK_RENAMED
RECOVERY_ROLLED_BACK
VERIFIED_OLD_OLD
RECOVERY_NO_JOURNAL
VERIFIED_OLD_OLD
REARMED_VERIFIED_OLD_OLD
USER_CONFIRMED_SYNTHETIC_CRASH
ARM_COMMIT_TEMP
RECOVERY_ROLLED_BACK
VERIFIED_OLD_OLD
```

**PASS sur vrai iPad (3/4)** : une fois les images installées et `committed.tmp` écrit, mais **avant la publication de `committed`**, la récupération a annulé la transaction puis vérifié les deux fichiers RTON synthétiques `OLD_OLD`. Le précédent audit, les deux premiers tests et les lignes de récupération sans journal sont toujours conservés. `ARM_COMMIT_TEMP` est l'étiquette de la phase demandée, tandis que `RECOVERY_ROLLED_BACK` / `VERIFIED_OLD_OLD` confirment la reprise effective. La conservation de la progression réelle du jeu n'est pas établie par ce log synthétique seul.

**Dernier checkpoint restant : « Après commit publié »**, à exécuter **en dernier** avec la même IPA et l'ancien laboratoire réarmé. Résultat attendu : `REARMED_VERIFIED_OLD_OLD` puis `USER_CONFIRMED_SYNTHETIC_CRASH`, `ARM_COMMIT_PUBLISHED`, `RECOVERY_COMMITTED` et `VERIFIED_NEW_NEW`. Après ce résultat, le réarmement sera volontairement refusé. Aucun nouveau build nécessaire. Ce protocole reste limité à un `SIGKILL` de processus, et ne simule pas une coupure d'alimentation iPadOS/APFS.
