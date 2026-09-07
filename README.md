# 🧭 GWC Analyzer

**Décompilateur et analyseur de cartouches Wherigo (`.gwc`)**, avec extraction automatique des coordonnées GPS, de l'inventaire, des médias, et désobfuscation du texte caché.

[![Ouvrir l'application](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://wiganalyzer.streamlit.app/)

👉 **[Essayer l'application en ligne](https://wiganalyzer.streamlit.app/)** — aucune installation nécessaire.

---

## ✨ Ce que fait l'outil

Une cartouche Wherigo (`.gwc`) est un format binaire propriétaire utilisé en geocaching. GWC Analyzer :

1. **Parse** le format `.gwc` (en-tête, métadonnées, table des objets).
2. **Extrait** le bytecode Lua compilé embarqué.
3. **Décompile** ce bytecode en code Lua lisible (via [`unluac`](https://sourceforge.net/projects/unluac/)).
4. **Désobfusque** automatiquement les chaînes de texte brouillées par le logiciel **Urwigo**.
5. **Recherche** des **coordonnées GPS** (plusieurs formats) et des **mots-clés** fournis par l'utilisateur.
6. **Génère** un rapport complet : texte en clair, code Lua annoté, liste des waypoints, inventaire des objets, et médias extraits (images, sons...).

Toutes les coordonnées sont automatiquement converties et affichées au format **DDM** (degrés/minutes décimales), le standard utilisé en geocaching — ex. `N 48° 12.348  E 002° 21.702`.

---

## 🖥️ Utiliser l'application web

L'app est déployée gratuitement sur Streamlit Community Cloud :

🔗 **https://wiganalyzer.streamlit.app/**

1. Upload ton fichier `.gwc`
2. (Optionnel) renseigne des mots-clés à rechercher
3. (Optionnel) coche "Extraire les fichiers médias" pour voir la galerie d'images/sons
4. Lance l'analyse et explore les résultats par onglet : texte clair (avec surlignage GPS/mots-clés), waypoints, inventaire, médias
5. Télécharge tous les résultats en un clic (`.zip`)

---

## 💻 Utiliser en ligne de commande (local)

Nécessite Python 3.8+ et un JRE Java (≥ 8) installé.

```bash
# Analyse simple (dossier de sortie automatique : <nom>_analyse/)
python3 gwc_analyzer.py cartouche.gwc

# Avec recherche de mots-clés
python3 gwc_analyzer.py cartouche.gwc --keywords "passeport,visa,indice"

# En précisant le dossier de sortie et en extrayant aussi les médias
python3 gwc_analyzer.py cartouche.gwc --output-dir sortie/ --media
```

## 🖼️ Interface graphique locale (Tkinter)

Une interface desktop est aussi disponible, sans rien installer de plus que Python :

```bash
python3 gwc_analyzer_gui.pyw
```

---

## 📁 Fichiers générés

| Fichier | Contenu |
|---|---|
| `texte_clair.txt` | Métadonnées + texte décodé + résultats de recherche GPS/mots-clés |
| `code_lua.txt` | Code Lua complet décompilé, annoté des chaînes décodées |
| `waypoints.txt` | Tous les points GPS (`ZonePoint`) — position de départ, zones, objets — au format DD et DDM |
| `inventaire.txt` | Tous les objets (`ZItem`) avec description et déplacements (`:MoveTo`) détectés |
| `log.txt` | Journal détaillé et horodaté de l'exécution |

---

## 🛠️ Stack technique

- **Python** (standard library uniquement pour la logique d'analyse — aucune dépendance externe)
- **[Streamlit](https://streamlit.io)** pour l'interface web
- **[unluac](https://sourceforge.net/projects/unluac/)** pour la décompilation du bytecode Lua 5.1 (fourni, licence MIT)
- **[jdk4py](https://pypi.org/project/jdk4py/)** pour embarquer un Java portable (nécessaire à `unluac`), sans dépendance système

---

## 📂 Structure du dépôt

```
├── app.py                  # Interface web Streamlit
├── gwc_analyzer.py         # Logique d'analyse (parsing, décompilation, extraction)
├── gwc_analyzer_gui.pyw    # Interface graphique desktop (Tkinter)
├── unluac.jar               # Décompilateur Lua (dépendance)
├── requirements.txt        # Dépendances Python (streamlit, jdk4py)
├── LICENSE_unluac.txt      # Licence MIT d'unluac
└── README.md
```

---

## ⚠️ Limites connues

- La détection de coordonnées GPS repose sur des expressions régulières couvrant les formats les plus courants en geocaching ; les formats très inhabituels ne seront pas repérés automatiquement, mais restent lisibles dans `texte_clair.txt`.
- Si une cartouche utilise un autre système d'obfuscation que celui d'Urwigo (ou aucune obfuscation), le script extrait les littéraux de chaîne visibles tels quels, sans désobfuscation.

---

## 📜 Licence

Ce projet utilise `unluac`, sous licence MIT (voir `LICENSE_unluac.txt`).
