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
