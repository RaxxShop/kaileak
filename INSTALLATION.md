# Site et administration — installation

Cette version remplace la maquette statique par un site autonome avec un serveur Python et une base SQLite. Elle s’inspire du design de S4NA mais ne se connecte pas à leurs comptes, fichiers ou services. Le catalogue commence vide : publie tes propres fichiers dans l’administration. La bannière et le logo de référence sont inclus ; remplace-les dans `public/assets` si tu changes de marque.

## Démarrage sous Windows

Prérequis : Python 3.11 ou plus récent, accessible avec `python` (aucune bibliothèque à installer).

1. Extrais complètement le ZIP dans un dossier.
2. Ouvre un terminal dans ce dossier.
3. Crée ton premier administrateur :

```text
python server.py create-admin
```

Indique ton adresse e-mail, ton nom et un mot de passe de 12 caractères minimum. Le mot de passe ne s’affiche pas pendant la saisie. Il n’existe aucun compte ou mot de passe par défaut.

4. Lance le site :

```text
python server.py serve
```

5. Ouvre `http://localhost:8000` dans ton navigateur. Clique sur « Se connecter », puis ouvre `http://localhost:8000/admin`.

Tu peux aussi utiliser `CREER_ADMIN.bat` puis `LANCER_SITE.bat`. Garde la fenêtre serveur ouverte ; Ctrl+C arrête le site. Si `python` n’est pas reconnu mais `py` fonctionne, utilise `py -3` à la place dans les commandes.

**N’ouvre pas directement le fichier index.html et ne lance pas ce projet avec Live Server.** Les comptes et les téléchargements ont besoin du serveur fourni.

## Première publication

- Administration → Ressources → Nouvelle ressource.
- Ajoute un titre, une description, une catégorie et le fichier (100 Mo maximum par défaut).
- L’image de couverture peut être une URL HTTPS ; elle est chargée directement par le navigateur.
- Coche « Publier dans le catalogue », puis enregistre.
- Un fichier est obligatoire pour publier. Une fiche sans fichier peut rester en brouillon.
- Teste le téléchargement depuis un compte membre. Les administrateurs ont accès aux fichiers VIP.

Les fichiers sont stockés en dehors du dossier public, avec un identifiant aléatoire. Le serveur les envoie en pièce jointe : ils ne sont jamais exécutés. Ils ne sont pas automatiquement analysés par un antivirus.

## Fonctions incluses

| Zone | Fonctionnement |
| --- | --- |
| Tableau de bord | Nombre de ressources publiées, utilisateurs, membres VIP et téléchargements commencés |
| Ressources | Création, édition, image par URL, catégories, fichiers, brouillons/publication et restriction VIP |
| Corbeille | Masquage et restauration sans suppression du fichier |
| Utilisateurs | Recherche, attribution/retrait VIP, rôle membre/admin, suspension/réactivation |
| Journal | 100 derniers événements : connexions et actions d’administration |
| Réglages | Nom, titre d’accueil, description, invitation Discord et ouverture/fermeture des inscriptions |
| Comptes | Inscription, connexion, déconnexion et changement de mot de passe |
| Catalogue | Recherche, filtres, tri et fiches alimentées par la base |
| Favoris | Enregistrés en base pour chaque compte |
| Téléchargements | Compte actif obligatoire ; vérification VIP et disponibilité côté serveur |

Une suspension invalide les sessions. Une modification du rôle invalide aussi les sessions du compte concerné. Tu ne peux pas te retirer ton propre accès admin ni supprimer le dernier administrateur actif. La création de comptes administrateurs initiaux se fait uniquement avec la commande locale.

## Données et sauvegardes

Le dossier `data/` est créé au premier lancement. Il contient `site.sqlite` et `files/`. Ne le place jamais dans un dossier public et ne le supprime pas lors d’une mise à jour.

Pour une sauvegarde cohérente, arrête le serveur puis lance :

```text
python server.py backup
```

Un ZIP horodaté est créé à la racine. Il contient la base et les fichiers, donc aussi des données personnelles et des informations de session : conserve-le en privé. Pour restaurer, arrête le serveur, conserve une copie de l’ancien dossier `data`, puis remplace-le par celui de la sauvegarde. Les anciens fichiers remplacés ou liés à des ressources en corbeille sont conservés ; aucune purge automatique n’est effectuée.

Pour réinitialiser un mot de passe depuis le terminal de l’hébergeur :

```text
python server.py reset-password
```

La commande demande l’adresse e-mail et le nouveau mot de passe, puis invalide les sessions du compte. Aucun e-mail de réinitialisation automatique n’est envoyé.

## Mise en ligne

Un VPS ou un hébergement capable d’exécuter un processus Python persistant est nécessaire. Un hébergement uniquement statique ou PHP ne suffit pas. Le serveur écoute par défaut sur `127.0.0.1` : utilise un reverse proxy HTTPS pour l’exposer sur ton domaine.

Variables d’environnement reconnues (le fichier d’exemple n’est pas chargé automatiquement) :

| Variable | Valeur par défaut | Utilité |
| --- | --- | --- |
| PUBLIC_ORIGIN | http://localhost:8000 | URL exacte du site, sans slash final ; contrôle Host/Origin et cookie Secure sous HTTPS |
| DATA_DIR | data à côté de server.py | Emplacement persistant de la base et des fichiers |
| MAX_UPLOAD_MB | 100 | Limite d’un fichier en Mo |
| TRUST_PROXY | 0 | Mettre à 1 seulement avec un reverse proxy local de confiance ; utilise sa dernière adresse X-Forwarded-For pour la limitation de connexion |

Exemple Linux avec un domaine déjà configuré :

```bash
export PUBLIC_ORIGIN=https://ton-domaine.fr
export DATA_DIR=/var/lib/mon-catalogue
export MAX_UPLOAD_MB=100
export TRUST_PROXY=1
python3 server.py serve --host 127.0.0.1 --port 8000
```

Exemple minimal de configuration Caddy (remplace le domaine) :

```text
ton-domaine.fr {
    reverse_proxy 127.0.0.1:8000
}
```

Configure le reverse proxy pour conserver le Host original, autoriser les tailles de fichiers souhaitées et limiter le trafic abusif. Fais tourner Python sous un utilisateur non privilégié et utilise un gestionnaire de processus de ton hébergeur pour les redémarrages. Aucun déploiement sur ton domaine ni certificat n’est configuré dans le ZIP.

## Sécurité et limites

- Mots de passe PBKDF2-SHA256 avec sel aléatoire et 600 000 itérations.
- Cookies de session HttpOnly et SameSite=Strict, Secure sous HTTPS ; expiration après 12 heures.
- Contrôle des rôles et du statut VIP sur le serveur, jeton CSRF pour les opérations connectées, contrôle de l’origine pour les écritures.
- Limitation à 12 tentatives de connexion/inscription par adresse IP sur 15 minutes, en mémoire du processus.
- Aucun secret d’API, compte de démonstration ou mot de passe livré.
- Pas de connexion Discord OAuth, paiement PayPal/Stripe, renouvellement automatique VIP, vérification d’e-mail, 2FA ou antivirus. Les VIP sont attribués manuellement.
- Pas de copie des ressources et de la base utilisateur du site original.
- Serveur autonome pour un petit catalogue : pas de stockage distribué, de pagination serveur ou d’optimisation pour un trafic important. Le serveur HTTP standard Python doit rester derrière un reverse proxy en ligne.
- Les images de couverture externes et les polices contactent leurs hébergeurs.

## Vérifications réalisées

`python test_server.py` lance une base temporaire et vérifie les parcours via HTTP : inscription sans élévation de rôle, connexion, refus d’accès admin pour un membre, CSRF, refus d’une origine tierce, upload, brouillons/publication, téléchargement VIP, favoris, corbeille/restauration, suspension, statistiques et changement de mot de passe avec invalidation de session. Le test ne touche pas à ta base réelle.

La syntaxe Python et JavaScript a aussi été vérifiée. Le rendu et les interactions n’ont pas été testés dans un navigateur sur cette version.
