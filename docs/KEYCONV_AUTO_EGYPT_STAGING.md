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
