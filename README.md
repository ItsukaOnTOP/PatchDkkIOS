# PatchDkkIOS / Transcend

Ce repo compile **IshinRedirect.dylib en standalone** : aucune dépendance à CydiaSubstrate, ElleKit, libhooker ou Substitute.

## Fichiers à garder dans le repo

```text
Redirect.m
Makefile
patch_transcend.py
.github/workflows/build.yml
.gitignore
README.md
```

Supprime les anciens `Tweak.x`, `control` et anciens workflows basés sur un tweak Substrate pour éviter de compiler le mauvais dylib.

## 1. Compiler le dylib sur GitHub

Après avoir poussé les fichiers :

1. GitHub → **Actions**
2. **Build Standalone Dylib**
3. **Run workflow**
4. Quand le build est fini, télécharge l'artifact **IshinRedirect-standalone**
5. Extrais `IshinRedirect.dylib`

Le workflow exécute `otool -L` et échoue s'il détecte une dépendance à Substrate / ElleKit / libhooker / Substitute.

## 2. Patcher l'IPA sur Windows

Place dans le même dossier :

```text
DokkanTranscend.ipa
IshinRedirect.dylib
patch_transcend.py
```

Puis :

```bat
python patch_transcend.py
```

Sortie :

```text
modded.ipa
```

Le patcher :
- ajoute/remplace `Frameworks/IshinRedirect.dylib` ;
- ajoute `LC_LOAD_DYLIB` dans le padding du header Mach-O sans déplacer le binaire ;
- change le bundle principal vers `com.Transcend.dbzdokkanGLB` ;
- change le nom de l'app vers `TRANSCEND` ;
- remplace la valeur de `dpuzzle/dpuzzlegamelayer/sparking` par `TRANSCEND!!!` dans les ressources localisées trouvées ;
- valide l'IPA finale.

## 3. Signer

Importe ensuite `modded.ipa` dans **KSign** et signe/installe l'IPA.

N'injecte pas une deuxième fois le dylib dans KSign : il est déjà intégré par `patch_transcend.py`.
