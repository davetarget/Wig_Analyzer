#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gwc_analyzer.py
================

Décompile un fichier cartouche Wherigo (.gwc) et en extrait :
  - les métadonnées de la cartouche (nom, auteur, GUID, position de départ, code
    de complétion, etc.) ;
  - le code Lua (bytecode compilé -> code source Lua lisible, grâce à unluac) ;
  - le texte "en clair", y compris les chaînes que les cartouches générées par
    Urwigo brouillent avec une fonction de substitution de caractères (le
    fameux "dtable") ;
  - une recherche de coordonnées GPS (plusieurs formats) et de mots-clés
    fournis par l'utilisateur dans tout ce texte.

Format binaire .gwc
--------------------
Référence utilisée pour le parsing (structure publique, documentée par le
projet WF.Compiler / gwcd) :

    @0000 BYTE 0x02, BYTE 0x0a, "CART", 0x00      -> signature
    @0007 USHORT NumberOfObjects
    @0009 répété NumberOfObjects fois :
              USHORT ObjectID
              INT    Address (offset absolu dans le fichier)
    Objet 0 = toujours le bytecode Lua compilé de la cartouche.
    Objets suivants = médias (jpg/png/bmp/gif/wav/mp3/txt/...).
    Puis un en-tête avec les métadonnées (nom, description, position de
    départ, auteur, société, code de complétion, etc.)

Décompilation Lua
-----------------
Les cartouches Wherigo embarquent du bytecode Lua 5.1 compilé (signature
"\\x1bLua\\x51"). Ce script utilise le décompilateur Java "unluac" (fourni,
unluac.jar, licence MIT) pour reconstituer un code Lua lisible. Java (>=8)
doit être installé (`java -version`).

Désobfuscation Urwigo
----------------------
De nombreuses cartouches sont générées par le logiciel "Urwigo", qui
remplace les chaînes de caractères par un appel à une fonction de
substitution du type :

    function XXXX(str)
      local res = ""
      local dtable = "<table de substitution de 127 caractères>"
      for i = 1, #str do
        local b = str:byte(i)
        if b > 0 and b <= 127 then
          res = res .. string.char(dtable:byte(b))
        else
          res = res .. string.char(b)
        end
      end
      return res
    end

Le nom de la fonction (XXXX) change à chaque compilation, mais le nom de la
variable locale "dtable" est stable (il vient du bytecode d'origine, les
noms de variables locales étant conservés dans le debug-info Lua). Ce script
détecte donc automatiquement cette fonction, puis décode tous les appels
`XXXX("...")` présents dans le code pour reconstituer le texte en clair.

Usage
-----
    python3 gwc_analyzer.py cartouche.gwc
    python3 gwc_analyzer.py cartouche.gwc --keywords "cyclope,passeport,visa"
    python3 gwc_analyzer.py cartouche.gwc --media --output-dir sortie/

Sorties (dans --output-dir, par défaut "<nom_du_gwc>_analyse/") :
    texte_clair.txt   -> métadonnées + tout le texte en clair + résultats
                         de recherche GPS / mots-clés
    code_lua.txt      -> code Lua décompilé complet (avec, en commentaire,
                         la valeur décodée de chaque chaîne obfusquée)
    waypoints.txt     -> tous les points GPS (ZonePoint) définis dans le
                         code : position de départ, zones, objets,
                         personnages... avec coordonnées décimales et
                         format degrés/minutes (DDM) habituel en geocaching
    cartridge.luac    -> bytecode Lua brut extrait (utile si vous voulez
                         le passer à un autre décompilateur)
    media_*.ext       -> fichiers médias (uniquement avec --media)
"""

import argparse
import logging
import os
import re
import struct
import subprocess
import sys
import shutil
import datetime

logger = logging.getLogger("gwc_analyzer")


def _no_window_kwargs():
    """Renvoie les arguments supplémentaires à passer à subprocess pour
    empêcher Windows d'ouvrir une fenêtre de console visible (le temps
    d'un flash) pour un sous-processus comme `java` ou `pip`. Sans effet
    sur Linux/Mac (l'indicateur n'existe pas sur ces plateformes)."""
    if sys.platform.startswith("win"):
        return {"creationflags": subprocess.CREATE_NO_WINDOW}
    return {}


def setup_logging(output_dir, extra_handlers=None):
    """Configure le logger pour écrire à la fois dans la console et dans
    un fichier log.txt (dans le dossier de sortie), avec horodatage.
    extra_handlers : handlers additionnels à rattacher après la
    réinitialisation (ex: pour afficher les logs dans une interface
    graphique en plus de la console et du fichier)."""
    logger.setLevel(logging.DEBUG)
    # Ferme proprement les anciens handlers avant de les retirer : un
    # logging.FileHandler garde son fichier ouvert (verrouillé sous
    # Windows) tant qu'il n'est pas explicitement fermé. Sans ce close(),
    # le log.txt d'une analyse précédente reste verrouillé tant que
    # l'application tourne, ce qui empêche par exemple sa suppression
    # (bouton "Effacer / Nettoyer" de la GUI).
    for old_handler in logger.handlers[:]:
        try:
            old_handler.close()
        except Exception:
            pass
    logger.handlers.clear()

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(console_handler)

    log_path = os.path.join(output_dir, "log.txt")
    file_handler = logging.FileHandler(log_path, mode="w", encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")
    )
    logger.addHandler(file_handler)

    for h in (extra_handlers or []):
        logger.addHandler(h)

    logger.debug(f"=== gwc_analyzer - démarré le {datetime.datetime.now().isoformat()} ===")
    logger.debug(f"Arguments : {sys.argv}")
    return log_path


# --------------------------------------------------------------------------
# 1. Lecture bas niveau du fichier .gwc
# --------------------------------------------------------------------------

class GWCFormatError(Exception):
    pass


OBJECT_TYPES = {
    1: "bmp", 2: "png", 3: "jpg", 4: "gif",
    17: "wav", 18: "mp3", 19: "fdl", 20: "snd", 21: "ogg", 33: "swf", 49: "txt",
}


class GWCFile:
    """Parseur du format binaire .gwc (cartouche Wherigo)."""

    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        self.pos = 0
        self.objects = []       # liste de (object_id, adresse)
        self.header = {}
        self._parse()

    # -- primitives de lecture --------------------------------------------
    def _read(self, fmt):
        size = struct.calcsize(fmt)
        chunk = self.data[self.pos:self.pos + size]
        if len(chunk) != size:
            raise GWCFormatError("Fichier .gwc tronqué ou corrompu")
        self.pos += size
        return struct.unpack(fmt, chunk)[0]

    def _read_cstring(self):
        end = self.data.index(b"\x00", self.pos)
        s = self.data[self.pos:end].decode("latin-1")
        self.pos = end + 1
        return s

    def _read_raw(self, length):
        chunk = self.data[self.pos:self.pos + length]
        self.pos += length
        return chunk

    # -- parsing principal --------------------------------------------------
    def _parse(self):
        # Signature
        sig_short = self._read("<H")
        magic = self._read_cstring()
        if sig_short != 0x0A02 or magic != "CART":
            raise GWCFormatError(
                "Signature .gwc invalide (fichier non reconnu comme cartouche Wherigo)"
            )

        # Table des objets
        nb_objects = self._read("<H")
        for _ in range(nb_objects):
            obj_id = self._read("<H")
            addr = self._read("<i")
            self.objects.append((obj_id, addr))

        # En-tête de métadonnées de la cartouche
        h = {}
        h["header_length"] = self._read("<i")
        h["latitude"] = self._read("<d")
        h["longitude"] = self._read("<d")
        h["altitude"] = self._read("<d")
        h["creation_date_raw"] = self._read("<q")
        h["splash_object_id"] = self._read("<h")
        h["icon_object_id"] = self._read("<h")
        h["cartridge_type"] = self._read_cstring()
        h["player"] = self._read_cstring()
        h["player_id"] = self._read("<q")
        h["name"] = self._read_cstring()
        h["guid"] = self._read_cstring()
        h["description"] = self._read_cstring()
        h["starting_location_description"] = self._read_cstring()
        h["version"] = self._read_cstring()
        h["author"] = self._read_cstring()
        h["company"] = self._read_cstring()
        h["recommended_device"] = self._read_cstring()
        completion_len = self._read("<i")
        h["completion_code"] = self._read_cstring()
        self.header = h

    # -- extraction des objets ----------------------------------------------
    def extract_lua_bytecode(self):
        """Retourne le bytecode Lua compilé (objet 0)."""
        for obj_id, addr in self.objects:
            if obj_id == 0:
                pos = addr
                length = struct.unpack("<i", self.data[pos:pos + 4])[0]
                pos += 4
                return self.data[pos:pos + length]
        raise GWCFormatError("Objet 0 (bytecode Lua) introuvable")

    def extract_media(self, output_dir):
        """Extrait tous les objets médias (images, sons, txt...) et
        renvoie la liste des chemins de fichiers créés."""
        created = []
        for obj_id, addr in self.objects:
            if obj_id == 0:
                continue
            pos = addr
            valid = self.data[pos]
            pos += 1
            if valid == 0:
                continue
            obj_type = struct.unpack("<i", self.data[pos:pos + 4])[0]
            pos += 4
            length = struct.unpack("<i", self.data[pos:pos + 4])[0]
            pos += 4
            content = self.data[pos:pos + length]
            ext = OBJECT_TYPES.get(obj_type, "bin")
            fname = f"media_{obj_id}.{ext}"
            fpath = os.path.join(output_dir, fname)
            with open(fpath, "wb") as f:
                f.write(content)
            created.append((fpath, obj_type, ext))
        return created


# --------------------------------------------------------------------------
# 2. Décompilation Lua (via unluac.jar)
# --------------------------------------------------------------------------

def find_unluac_jar(explicit_path=None):
    candidates = []
    if explicit_path:
        candidates.append(explicit_path)
    if getattr(sys, "frozen", False):
        # Cas d'un exécutable créé avec PyInstaller : on cherche à côté
        # du .exe, pas à côté du script source (qui n'existe plus).
        here = os.path.dirname(os.path.abspath(sys.executable))
    else:
        here = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(here, "unluac.jar"))
    candidates.append("unluac.jar")
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return None


def decompile_lua(luac_path, jar_path):
    """Appelle `java -jar unluac.jar fichier.luac` et retourne le code
    source Lua reconstitué (str). Lève RuntimeError si java/jar absent
    ou en cas d'échec. Toute la commande et sa sortie sont journalisées."""
    if shutil.which("java") is None:
        logger.error("Java introuvable dans le PATH (commande 'java').")
        raise RuntimeError(
            "Java n'est pas installé ou introuvable dans le PATH. "
            "Installez un JRE (>=8) pour permettre la décompilation du "
            "bytecode Lua (ex: apt install default-jre)."
        )
    if not jar_path or not os.path.isfile(jar_path):
        logger.error(f"unluac.jar introuvable (chemin testé : {jar_path}).")
        raise RuntimeError(
            "unluac.jar introuvable. Placez-le à côté de gwc_analyzer.py "
            "ou indiquez son chemin avec --unluac chemin/vers/unluac.jar."
        )
    cmd = ["java", "-jar", jar_path, luac_path]
    logger.debug(f"Commande exécutée : {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, **_no_window_kwargs())
    logger.debug(f"unluac - code de retour : {result.returncode}")
    if result.stderr:
        logger.debug("unluac - sortie d'erreur (stderr) :\n" + result.stderr)
    logger.debug(f"unluac - taille de la sortie (stdout) : {len(result.stdout)} caractères")
    if result.returncode != 0:
        raise RuntimeError(
            f"Échec de la décompilation avec unluac :\n{result.stderr}"
        )
    return result.stdout


# --------------------------------------------------------------------------
# 3. Désobfuscation des chaînes "Urwigo" (table de substitution)
# --------------------------------------------------------------------------

def parse_lua_string_literal(escaped):
    """Convertit le contenu (sans les guillemets) d'un littéral de chaîne
    Lua tel qu'émis par unluac en bytes bruts, en gérant les échappements
    \\n \\t \\\\ \\" \\ddd etc."""
    out = bytearray()
    i = 0
    simple = {
        "n": 10, "t": 9, "a": 7, "b": 8, "f": 12, "r": 13, "v": 11,
        "\\": 92, '"': 34, "'": 39,
    }
    while i < len(escaped):
        c = escaped[i]
        if c == "\\":
            i += 1
            if i >= len(escaped):
                break
            nc = escaped[i]
            if nc.isdigit():
                num = nc
                i += 1
                for _ in range(2):
                    if i < len(escaped) and escaped[i].isdigit():
                        num += escaped[i]
                        i += 1
                    else:
                        break
                out.append(int(num) % 256)
                continue
            if nc in simple:
                out.append(simple[nc])
                i += 1
                continue
            out.append(ord(nc))
            i += 1
            continue
        else:
            out.append(ord(c))
            i += 1
    return bytes(out)


DTABLE_RE = re.compile(r'local\s+dtable\s*=\s*"((?:\\.|[^"\\])*)"')
FUNC_DEF_RE = re.compile(r'function\s+([A-Za-z_][A-Za-z0-9_.]*)\s*\(')


def find_obfuscation_scheme(lua_source):
    """Cherche la fonction de désobfuscation générée par Urwigo (variable
    locale caractéristique `dtable`). Retourne (nom_fonction, dtable_bytes)
    ou (None, None) si le schéma n'est pas trouvé."""
    m = DTABLE_RE.search(lua_source)
    if not m:
        return None, None
    dtable = parse_lua_string_literal(m.group(1))
    if len(dtable) < 100:
        return None, None

    # Cherche la définition de fonction la plus proche AVANT le "dtable"
    func_name = None
    for fm in FUNC_DEF_RE.finditer(lua_source[:m.start()]):
        func_name = fm.group(1)
    return func_name, dtable


def deobfuscate_bytes(raw, dtable):
    out = bytearray()
    for b in raw:
        if 0 < b <= 127:
            out.append(dtable[b - 1])
        else:
            out.append(b)
    return bytes(out)


def decode_obfuscated_calls(lua_source, func_name, dtable):
    """Trouve tous les appels func_name("...") ou func_name('...') et
    retourne une liste de (chaine_originale_echappee, texte_décodé)."""
    if not func_name:
        return []
    pattern = re.compile(
        re.escape(func_name) + r'\(\s*"((?:\\.|[^"\\])*)"\s*\)'
        + r'|' + re.escape(func_name) + r"\(\s*'((?:\\.|[^'\\])*)'\s*\)"
    )
    results = []
    for m in pattern.finditer(lua_source):
        escaped = m.group(1) if m.group(1) is not None else m.group(2)
        raw = parse_lua_string_literal(escaped)
        decoded = deobfuscate_bytes(raw, dtable)
        try:
            text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            text = decoded.decode("latin-1")
        results.append((escaped, text))
    return results


# --------------------------------------------------------------------------
# 4. Extraction des littéraux de chaînes "en clair" (non obfusquées)
# --------------------------------------------------------------------------

STRING_LITERAL_RE = re.compile(r'"((?:\\.|[^"\\])*)"')


def extract_plain_string_literals(lua_source, min_len=3):
    """Récupère tous les littéraux de chaîne du code Lua décompilé (qu'ils
    soient obfusqués ou non - la désobfuscation est faite séparément)."""
    seen = []
    for m in STRING_LITERAL_RE.finditer(lua_source):
        raw = parse_lua_string_literal(m.group(1))
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1")
        if len(text.strip()) >= min_len:
            seen.append(text)
    return seen


def looks_readable(text, min_len=2, threshold=0.95):
    """Heuristique simple : une chaîne est considérée comme du texte
    lisible si elle contient une forte proportion de caractères
    imprimables (lettres, ponctuation, espaces, retours à la ligne...)."""
    if not text or len(text) < min_len:
        return False
    printable = sum(1 for c in text if c.isprintable() or c in "\n\t")
    return printable / len(text) >= threshold


def recover_hidden_obfuscated_strings(literals, func_name, dtable):
    """decode_obfuscated_calls() ne repère que les chaînes passées
    directement en argument d'un appel `FONCTION("...")`. Or certaines
    cartouches stockent d'abord la chaîne chiffrée dans une variable
    intermédiaire avant d'appeler la fonction dessus - ces chaînes
    échappent alors totalement à la détection et restent affichées comme
    du charabia illisible dans "AUTRES LITTÉRAUX".

    Cette fonction tente de déchiffrer, avec la même table de
    substitution, TOUT littéral qui ne ressemble pas déjà à du texte
    lisible, et ne conserve le résultat que s'il devient lisible - ce qui
    permet de récupérer ce texte cachée sans jamais risquer d'altérer un
    littéral qui n'avait pas besoin d'être déchiffré (un GUID, une date,
    un nom de fichier... sont déjà lisibles et ne sont donc jamais
    passés au déchiffrement).

    Retourne (textes_recuperes, littéraux_restants) : les littéraux
    restants regroupent ceux qui étaient déjà lisibles tels quels et ceux
    qui restent illisibles même après tentative de déchiffrement (le plus
    souvent la table de substitution elle-même, qui ne peut évidemment
    pas se déchiffrer avec elle-même)."""
    recovered = []
    remaining = []
    if not (func_name and dtable):
        return recovered, list(literals)
    for lit in literals:
        if looks_readable(lit):
            remaining.append(lit)
            continue
        try:
            raw = lit.encode("latin-1")
        except UnicodeEncodeError:
            remaining.append(lit)
            continue
        decoded_bytes = deobfuscate_bytes(raw, dtable)
        try:
            decoded_text = decoded_bytes.decode("utf-8")
        except UnicodeDecodeError:
            decoded_text = decoded_bytes.decode("latin-1", errors="replace")
        if looks_readable(decoded_text):
            recovered.append(decoded_text)
        else:
            remaining.append(lit)
    return recovered, remaining


# --------------------------------------------------------------------------
# 5. Extraction des waypoints (ZonePoint) du code Lua
# --------------------------------------------------------------------------

ZONEPOINT_RE = re.compile(
    r'(?:Wherigo\.)?ZonePoint\(\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*'
    r'(?:,\s*(-?\d+(?:\.\d+)?)\s*)?\)'
)
ASSIGN_RE = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s*=')


def decimal_to_ddm(lat, lon):
    """Convertit des degrés décimaux en notation degrés/minutes décimales,
    format habituel en geocaching (ex: N 48° 12.345 E 002° 21.678)."""
    def part(value, pos_letter, neg_letter):
        letter = pos_letter if value >= 0 else neg_letter
        value = abs(value)
        deg = int(value)
        minutes = (value - deg) * 60
        return f"{letter} {deg:02d}\u00b0 {minutes:06.3f}"
    return f"{part(lat, 'N', 'S')}  {part(lon, 'E', 'W')}"


def find_field_for_variable(lua_source, base_var, field, func_name, dtable):
    """Cherche `base_var.<field> = "..."` (ou un appel obfusqué) dans le
    code et retourne le texte décodé le cas échéant, sinon None."""
    if not base_var:
        return None
    pattern = re.compile(
        re.escape(base_var) + r'\.' + re.escape(field) + r'\s*=\s*"((?:\\.|[^"\\])*)"'
    )
    m = pattern.search(lua_source)
    if m:
        raw = parse_lua_string_literal(m.group(1))
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("latin-1")
    if func_name and dtable:
        pattern2 = re.compile(
            re.escape(base_var) + r'\.' + re.escape(field) + r'\s*=\s*'
            + re.escape(func_name) + r'\(\s*"((?:\\.|[^"\\])*)"\s*\)'
        )
        m2 = pattern2.search(lua_source)
        if m2:
            raw = parse_lua_string_literal(m2.group(1))
            decoded = deobfuscate_bytes(raw, dtable)
            try:
                return decoded.decode("utf-8")
            except UnicodeDecodeError:
                return decoded.decode("latin-1")
    return None


def find_name_for_variable(lua_source, base_var, func_name, dtable):
    """Raccourci : cherche spécifiquement le champ .Name."""
    return find_field_for_variable(lua_source, base_var, "Name", func_name, dtable)


def find_waypoints_in_code(lua_source, func_name, dtable):
    """Parcourt le code Lua décompilé à la recherche de tous les appels
    ZonePoint(lat, lon[, alt]), qui correspondent aux emplacements réels
    (position de départ, zones, objets, personnages...) définis dans la
    cartouche. Retourne une liste de dicts."""
    if not lua_source:
        return []
    lines = lua_source.splitlines()
    waypoints = []
    name_cache = {}
    for i, line in enumerate(lines):
        for m in ZONEPOINT_RE.finditer(line):
            lat = float(m.group(1))
            lon = float(m.group(2))
            alt = float(m.group(3)) if m.group(3) is not None else 0.0
            # Filtre les valeurs invalides (hors plage GPS réelle)
            if abs(lat) > 90 or abs(lon) > 180:
                continue
            label = None
            am = ASSIGN_RE.match(line)
            if am:
                label = am.group(1)
            else:
                for j in range(i - 1, max(-1, i - 15), -1):
                    am2 = ASSIGN_RE.match(lines[j])
                    if am2:
                        label = am2.group(1)
                        break
            base_var = label.split(".")[0] if label else None
            if base_var not in name_cache:
                name_cache[base_var] = find_name_for_variable(
                    lua_source, base_var, func_name, dtable
                )
            waypoints.append({
                "line": i + 1,
                "label": label or "(inconnu)",
                "name": name_cache.get(base_var),
                "lat": lat,
                "lon": lon,
                "alt": alt,
            })
    return waypoints


# --------------------------------------------------------------------------
# 5bis. Extraction de l'inventaire (ZItem) et des déplacements (:MoveTo)
# --------------------------------------------------------------------------

OBJECT_DECL_RE = re.compile(r'([A-Za-z_]\w*)\s*=\s*Wherigo\.(Zone|ZItem|ZCharacter)\s*\(')
MOVETO_RE = re.compile(r'([A-Za-z_]\w*)\s*:\s*MoveTo\(\s*([A-Za-z_]\w*)\s*\)')

OBJECT_TYPE_LABELS = {"Zone": "zone", "ZItem": "objet", "ZCharacter": "personnage"}


def find_object_catalog(lua_source, func_name, dtable):
    """Recense toutes les déclarations d'objets Wherigo (Zone, ZItem,
    ZCharacter) du code et résout leur nom (désobfusqué si besoin).
    Retourne un dict {variable: {"type": ..., "name": ...}}."""
    catalog = {}
    if not lua_source:
        return catalog
    for m in OBJECT_DECL_RE.finditer(lua_source):
        var, obj_type = m.group(1), m.group(2)
        if var in catalog:
            continue
        name = find_name_for_variable(lua_source, var, func_name, dtable)
        catalog[var] = {"type": obj_type, "name": name}
    return catalog


def _resolve_container_label(target_var, catalog):
    if target_var == "Player":
        return "Joueur (inventaire)"
    if target_var == "nil":
        return "Retiré du jeu (masqué)"
    info = catalog.get(target_var)
    if info:
        label = OBJECT_TYPE_LABELS.get(info["type"], info["type"])
        name = info["name"] or "(nom non trouvé)"
        return f"{name} ({label})"
    return target_var


def find_inventory_items(lua_source, func_name, dtable):
    """Repère tous les objets ZItem déclarés dans le code, avec leur nom,
    leur description, et tous les déplacements `:MoveTo(cible)` trouvés
    dans le code (le mécanisme standard Wherigo pour placer un objet dans
    l'inventaire du joueur, une zone, ou un autre objet). Une cartouche
    Wherigo ne déclare presque jamais l'emplacement initial d'un objet de
    façon statique (`.Container = ...`) : le placement se fait presque
    toujours dynamiquement via ces appels `:MoveTo()`, en général au sein
    d'un gestionnaire d'événement (ex: après avoir résolu une énigme). Un
    objet peut donc apparaître avec plusieurs déplacements possibles
    (selon le scénario), ou aucun si son emplacement ne change jamais
    dans le code (ou dépend d'une logique trop complexe pour être
    détectée statiquement)."""
    if not lua_source:
        return []
    catalog = find_object_catalog(lua_source, func_name, dtable)

    moves_by_var = {}
    for m in MOVETO_RE.finditer(lua_source):
        source_var, target_var = m.group(1), m.group(2)
        moves_by_var.setdefault(source_var, []).append(target_var)

    items = []
    for var, info in catalog.items():
        if info["type"] != "ZItem":
            continue
        description = find_field_for_variable(lua_source, var, "Description", func_name, dtable)
        raw_moves = moves_by_var.get(var, [])
        seen = set()
        movements = []
        for target_var in raw_moves:
            label = _resolve_container_label(target_var, catalog)
            if label not in seen:
                seen.add(label)
                movements.append(label)
        items.append({
            "variable": var,
            "name": info["name"] or "(nom non trouvé)",
            "description": description or "",
            "movements": movements,
        })
    return items


def _parse_ddm_pair(m):
    """N 48° 12.345 E 002° 21.678 -> (lat, lon) en degrés décimaux."""
    ns, deg1, min1, ew, deg2, min2 = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5), m.group(6)
    lat = float(deg1) + float(min1.replace(",", ".")) / 60
    if ns.upper() == "S":
        lat = -lat
    lon = float(deg2) + float(min2.replace(",", ".")) / 60
    if ew.upper() in ("W", "O"):
        lon = -lon
    return f"DD : {lat:.6f}, {lon:.6f}"


def _parse_dms_single(m):
    """48°12'34.5"N -> DD (une seule coordonnée, latitude ou longitude)."""
    deg, minute, sec, hemi = m.group(1), m.group(2), m.group(3), m.group(4)
    value = float(deg) + float(minute) / 60 + float(sec.replace(",", ".")) / 3600
    if hemi.upper() in ("S", "W", "O"):
        value = -value
    axis = "latitude" if hemi.upper() in ("N", "S") else "longitude"
    return f"DD ({axis}) : {value:.6f}"


def _parse_ddm_single(m):
    """N 48° 12.345 -> DD (une seule coordonnée, latitude ou longitude)."""
    hemi, deg, minute = m.group(1), m.group(2), m.group(3)
    value = float(deg) + float(minute.replace(",", ".")) / 60
    if hemi.upper() in ("S", "W", "O"):
        value = -value
    axis = "latitude" if hemi.upper() in ("N", "S") else "longitude"
    return f"DD ({axis}) : {value:.6f}"


def _parse_dd_pair(m):
    """48.123456, 2.123456 (déjà en DD) -> fournit l'équivalent DDM."""
    lat, lon = float(m.group(1)), float(m.group(2))
    return f"DDM : {decimal_to_ddm(lat, lon)}"


# Chaque entrée : (motif avec groupes de capture, fonction de conversion en DD
# ou None si le motif est déjà en DD et ne nécessite pas de conversion).
# L'ordre compte : les motifs les plus spécifiques (paires complètes) sont
# placés en premier, pour être prioritaires sur les motifs "coordonnée seule"
# qui pourraient sinon matcher une simple portion d'une paire déjà détectée.
GPS_PATTERNS = [
    # Degrés décimaux minutes façon geocaching : N 48° 12.345 E 002° 21.678
    # (le symbole ° est optionnel : certaines cartouches l'omettent et
    # écrivent juste "N 48 12.345", un simple espace suffit à séparer les
    # degrés des minutes).
    (
        re.compile(
            r'([NS])\s*(\d{1,2})\s*[°ºo]?\s+(\d{1,2}(?:[.,]\d+)?)\s*\'?'
            r'\D{0,6}'
            r'([EWO])\s*(\d{1,3})\s*[°ºo]?\s+(\d{1,2}(?:[.,]\d+)?)\s*\'?',
            re.IGNORECASE,
        ),
        _parse_ddm_pair,
    ),
    # Degrés minutes secondes : 48°12'34.5"N (une seule coordonnée à la fois)
    (
        re.compile(
            r'(\d{1,3})[°ºo]\s*(\d{1,2})\'\s*(\d{1,2}(?:[.,]\d+)?)"?\s*([NSEWO])',
            re.IGNORECASE,
        ),
        _parse_dms_single,
    ),
    # Degrés décimaux simples : 48.123456, 2.123456 (déjà en DD -> ajoute le DDM)
    (
        re.compile(r'(-?\d{1,3}\.\d{3,8})\s*[,;]\s*(-?\d{1,3}\.\d{3,8})'),
        _parse_dd_pair,
    ),
    # Juste une lettre N/S/E/W suivie de chiffres (une seule coordonnée,
    # symbole ° optionnel, cf. remarque ci-dessus)
    (
        re.compile(
            r'([NSEWO])\s*(\d{1,3})\s*[°ºo]?\s+(\d{1,2}(?:[.,]\d+)?)', re.IGNORECASE
        ),
        _parse_ddm_single,
    ),
]


def find_gps_matches(text_blocks):
    """text_blocks : itérable de (source_label, texte). Retourne une liste
    de (source_label, extrait_trouvé, conversion_dd_ou_None). Chaque
    coordonnée détectée dans un format autre que DD (degrés décimaux) est
    accompagnée de sa conversion en DD."""
    matches = []
    for label, text in text_blocks:
        if not text:
            continue
        occupied_spans = []
        for pattern, parser in GPS_PATTERNS:
            for m in pattern.finditer(text):
                start, end = m.span()
                if any(start < e and s < end for s, e in occupied_spans):
                    continue  # chevauche une correspondance déjà retenue (motif plus spécifique)
                occupied_spans.append((start, end))
                raw = m.group(0).strip()
                conversion = parser(m) if parser else None
                matches.append((label, raw, conversion))
    # dédoublonnage en conservant l'ordre
    dedup = []
    seen = set()
    for label, raw, conversion in matches:
        key = (label, raw)
        if key not in seen:
            seen.add(key)
            dedup.append((label, raw, conversion))
    return dedup


def find_keyword_matches(text_blocks, keywords):
    """Recherche insensible à la casse de chaque mot-clé dans chaque bloc
    de texte, avec un court contexte autour de l'occurrence."""
    matches = []
    for label, text in text_blocks:
        if not text:
            continue
        low = text.lower()
        for kw in keywords:
            kw_low = kw.lower().strip()
            if not kw_low:
                continue
            start = 0
            while True:
                idx = low.find(kw_low, start)
                if idx == -1:
                    break
                ctx_start = max(0, idx - 40)
                ctx_end = min(len(text), idx + len(kw) + 40)
                context = text[ctx_start:ctx_end].replace("\n", " ")
                matches.append((label, kw, context))
                start = idx + len(kw_low)
    return matches


# --------------------------------------------------------------------------
# 6. Programme principal
# --------------------------------------------------------------------------

def format_header(h, include_ddm=True):
    lines = []
    lines.append(f"Nom de la cartouche      : {h.get('name','')}")
    lines.append(f"GUID                     : {h.get('guid','')}")
    lines.append(f"Type                     : {h.get('cartridge_type','')}")
    lines.append(f"Auteur                   : {h.get('author','')}")
    lines.append(f"Société                  : {h.get('company','')}")
    lines.append(f"Version                  : {h.get('version','')}")
    lines.append(f"Appareil recommandé      : {h.get('recommended_device','')}")
    lines.append(f"Téléchargé par           : {h.get('player','')} (id {h.get('player_id','')})")
    lat, lon, alt = h.get('latitude'), h.get('longitude'), h.get('altitude')
    if lat is not None and abs(lat) <= 90 and abs(lon) <= 180:
        lines.append(f"Position de départ      : {lat:.6f}, {lon:.6f} (altitude {alt} m)")
        if include_ddm:
            lines.append(f"Position de départ (DDM) : {decimal_to_ddm(lat, lon)}")
    else:
        lines.append(f"Position de départ      : non définie (valeurs brutes : {lat}, {lon}, {alt})")
    lines.append(f"Description départ       : {h.get('starting_location_description','')}")
    lines.append(f"Code de complétion       : {h.get('completion_code','')}")
    lines.append("")
    lines.append("Description complète :")
    lines.append(h.get("description", ""))
    return "\n".join(lines)


def run_analysis(gwc_file, output_dir=None, unluac_path=None, keywords="",
                  media=False, extra_log_handlers=None):
    """Exécute l'analyse complète d'une cartouche .gwc. Peut être appelée
    directement (ex: depuis l'interface graphique) sans passer par un
    sous-processus ni par argparse. Lève une exception en cas d'erreur
    bloquante. Retourne un dict avec les chemins de sortie et les
    données structurées utiles à un appelant programmatique (GUI)."""
    if not os.path.isfile(gwc_file):
        raise FileNotFoundError(f"Fichier introuvable : {gwc_file}")

    base = os.path.splitext(os.path.basename(gwc_file))[0]
    output_dir = output_dir or f"{base}_analyse"
    os.makedirs(output_dir, exist_ok=True)
    log_path = setup_logging(output_dir, extra_handlers=extra_log_handlers)

    logger.info(f"[1/8] Lecture de {gwc_file} ...")
    gwc = GWCFile(gwc_file)
    logger.info(f"      -> {len(gwc.objects)} objets trouvés dans la cartouche.")

    logger.info("[2/8] Extraction du bytecode Lua ...")
    luac_bytes = gwc.extract_lua_bytecode()
    luac_path = os.path.join(output_dir, "cartridge.luac")
    with open(luac_path, "wb") as f:
        f.write(luac_bytes)
    logger.info(f"      -> {len(luac_bytes)} octets écrits dans {luac_path}")

    logger.info("[3/8] Décompilation du bytecode Lua (unluac) ...")
    jar_path = find_unluac_jar(unluac_path)
    lua_source = ""
    try:
        lua_source = decompile_lua(luac_path, jar_path)
        logger.info(f"      -> {len(lua_source.splitlines())} lignes de code Lua reconstituées.")
    except RuntimeError as e:
        logger.error(f"{e}")
        lua_source = ""

    logger.info("[4/8] Recherche du schéma de désobfuscation Urwigo (table 'dtable') ...")
    func_name, dtable = find_obfuscation_scheme(lua_source) if lua_source else (None, None)
    decoded_calls = []
    if func_name and dtable:
        logger.info(f"      -> Fonction de désobfuscation détectée : {func_name}()")
        decoded_calls = decode_obfuscated_calls(lua_source, func_name, dtable)
        logger.info(f"      -> {len(decoded_calls)} chaînes obfusquées décodées.")
    else:
        logger.info("      -> Aucun schéma de désobfuscation détecté (le code n'est peut-être pas obfusqué).")

    plain_literals = []
    recovered_hidden_texts = []
    if lua_source:
        logger.info("[5/8] Extraction des littéraux de chaînes visibles dans le code ...")
        plain_literals = extract_plain_string_literals(lua_source)
        logger.info(f"      -> {len(plain_literals)} littéraux trouvés.")
        if func_name and dtable:
            recovered_hidden_texts, plain_literals = recover_hidden_obfuscated_strings(
                plain_literals, func_name, dtable
            )
            if recovered_hidden_texts:
                logger.info(
                    f"      -> {len(recovered_hidden_texts)} chaîne(s) cachée(s) supplémentaire(s) "
                    "récupérée(s) (appels indirects, via variable intermédiaire)."
                )

    media_files = []
    media_dir = None
    if media:
        media_dir = os.path.join(output_dir, "media")
        os.makedirs(media_dir, exist_ok=True)
        logger.info("[extra] Extraction des fichiers médias ...")
        media_files = gwc.extract_media(media_dir)
        logger.info(f"      -> {len(media_files)} fichiers médias extraits dans {media_dir}")

    logger.info("[6/8] Extraction des waypoints (ZonePoint) définis dans le code ...")
    waypoints = find_waypoints_in_code(lua_source, func_name, dtable)
    logger.info(f"      -> {len(waypoints)} waypoint(s) trouvé(s) dans le code Lua.")

    logger.info("[7/8] Extraction de l'inventaire (objets ZItem) définis dans le code ...")
    inventory_items = find_inventory_items(lua_source, func_name, dtable)
    logger.info(f"      -> {len(inventory_items)} objet(s) trouvé(s) dans le code Lua.")

    logger.info("[8/8] Recherche de coordonnées GPS et de mots-clés ...")
    keywords_list = [k for k in keywords.split(",") if k.strip()]

    text_blocks = []
    text_blocks.append(("Métadonnées cartouche", format_header(gwc.header, include_ddm=False)))
    for escaped, decoded in decoded_calls:
        text_blocks.append((f"Chaîne décodée ({func_name})", decoded))
    for text in recovered_hidden_texts:
        text_blocks.append((f"Chaîne cachée récupérée ({func_name})", text))
    for lit in plain_literals:
        text_blocks.append(("Littéral de code Lua", lit))
    for it in inventory_items:
        if it["description"]:
            text_blocks.append((f"Objet : {it['name']}", it["description"]))

    gps_matches = find_gps_matches(text_blocks)
    keyword_matches = find_keyword_matches(text_blocks, keywords_list) if keywords_list else []

    # ---- écriture texte_clair.txt ----
    texte_clair_path = os.path.join(output_dir, "texte_clair.txt")
    texte_clair_content_parts = []

    def w(s):
        texte_clair_content_parts.append(s)

    w("=" * 70 + "\n")
    w("MÉTADONNÉES DE LA CARTOUCHE\n")
    w("=" * 70 + "\n")
    w(format_header(gwc.header) + "\n\n")

    w("=" * 70 + "\n")
    total_decoded = len(decoded_calls) + len(recovered_hidden_texts)
    w(f"CHAÎNES DÉSOBFUSQUÉES ({total_decoded} trouvées, fonction: {func_name})\n")
    if recovered_hidden_texts:
        w(
            f"(dont {len(decoded_calls)} via appels directs et "
            f"{len(recovered_hidden_texts)} récupérées via analyse complémentaire "
            "- chaînes stockées dans une variable avant d'être déchiffrées)\n"
        )
    w("=" * 70 + "\n")
    counts = {}
    for _, decoded in decoded_calls:
        counts[decoded] = counts.get(decoded, 0) + 1
    for text in recovered_hidden_texts:
        counts[text] = counts.get(text, 0) + 1
    for text, n in sorted(counts.items(), key=lambda x: -x[1]):
        if text.strip():
            suffix = f"  (x{n})" if n > 1 else ""
            w(f"- {text}{suffix}\n")
    w("\n")

    w("=" * 70 + "\n")
    w(f"AUTRES LITTÉRAUX DE TEXTE DANS LE CODE ({len(plain_literals)} trouvés)\n")
    w("=" * 70 + "\n")
    uniq_literals = sorted(set(l for l in plain_literals if l.strip()))
    for lit in uniq_literals:
        w(f"- {lit}\n")
    w("\n")

    w("=" * 70 + "\n")
    w(f"COORDONNÉES GPS DÉTECTÉES ({len(gps_matches)})\n")
    w("=" * 70 + "\n")
    if gps_matches:
        for label, val, conversion in gps_matches:
            if conversion:
                w(f"[{label}] {val}  →  {conversion}\n")
            else:
                w(f"[{label}] {val}\n")
    else:
        w("(aucune coordonnée détectée par les motifs de recherche actuels)\n")
    w("\n")

    w("=" * 70 + "\n")
    w(f"MOTS-CLÉS RECHERCHÉS : {', '.join(keywords_list) if keywords_list else '(aucun fourni)'}\n")
    w(f"OCCURRENCES TROUVÉES : {len(keyword_matches)}\n")
    w("=" * 70 + "\n")
    for label, kw, context in keyword_matches:
        w(f"[{label}] mot-clé '{kw}' : ...{context}...\n")

    texte_clair_content = "".join(texte_clair_content_parts)
    with open(texte_clair_path, "w", encoding="utf-8") as f:
        f.write(texte_clair_content)

    # ---- écriture code_lua.txt ----
    code_lua_path = os.path.join(output_dir, "code_lua.txt")
    with open(code_lua_path, "w", encoding="utf-8") as f:
        f.write("-- Code Lua décompilé depuis le bytecode de la cartouche .gwc\n")
        f.write(f"-- Source : {gwc_file}\n")
        if func_name:
            f.write(f"-- Fonction de désobfuscation Urwigo détectée : {func_name}()\n")
            f.write("-- Chaque appel obfusqué est annoté juste après par la valeur décodée.\n")
        f.write("\n")
        if lua_source:
            if func_name and dtable:
                pattern = re.compile(
                    re.escape(func_name) + r'\(\s*"(?:\\.|[^"\\])*"\s*\)'
                    + r'|' + re.escape(func_name) + r"\(\s*'(?:\\.|[^'\\])*'\s*\)"
                )

                def annotate(m):
                    call = m.group(0)
                    inner = STRING_LITERAL_RE.search(call)
                    if not inner:
                        return call
                    raw = parse_lua_string_literal(inner.group(1))
                    decoded = deobfuscate_bytes(raw, dtable)
                    try:
                        decoded_text = decoded.decode("utf-8")
                    except UnicodeDecodeError:
                        decoded_text = decoded.decode("latin-1")
                    decoded_text = decoded_text.replace("\n", "\\n")
                    return f'{call} --[[= "{decoded_text}" ]]'

                annotated_source = pattern.sub(annotate, lua_source)
                f.write(annotated_source)
            else:
                f.write(lua_source)
        else:
            f.write("-- La décompilation a échoué : voir les messages affichés par le script.\n")
            f.write("-- Le bytecode brut reste disponible dans cartridge.luac.\n")

    # ---- écriture waypoints.txt + préparation données structurées ----
    lat, lon, alt = gwc.header.get("latitude"), gwc.header.get("longitude"), gwc.header.get("altitude")
    header_valid = lat is not None and abs(lat) <= 90 and abs(lon) <= 180
    starting_location = {"lat": lat, "lon": lon, "alt": alt} if header_valid else None

    waypoints_path = os.path.join(output_dir, "waypoints.txt")
    with open(waypoints_path, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("WAYPOINTS DÉTECTÉS DANS LA CARTOUCHE\n")
        f.write("=" * 70 + "\n\n")

        if header_valid:
            f.write("[En-tête cartouche] Position de départ (StartingLocation)\n")
            f.write(f"  Décimal : {lat:.6f}, {lon:.6f}  (altitude {alt} m)\n")
            f.write(f"  DDM     : {decimal_to_ddm(lat, lon)}\n\n")
        else:
            f.write("[En-tête cartouche] Aucune position de départ valide définie "
                    f"(valeurs brutes : {lat}, {lon}, {alt})\n\n")

        f.write(f"Waypoints trouvés dans le code Lua décompilé : {len(waypoints)}\n")
        f.write("-" * 70 + "\n")
        if waypoints:
            for idx, wp in enumerate(waypoints, start=1):
                nom = wp["name"] or "(nom non trouvé)"
                f.write(f"#{idx} - ligne {wp['line']} - {wp['label']}\n")
                f.write(f"     Nom      : {nom}\n")
                f.write(f"     Décimal  : {wp['lat']:.6f}, {wp['lon']:.6f}  (altitude {wp['alt']} m)\n")
                f.write(f"     DDM      : {decimal_to_ddm(wp['lat'], wp['lon'])}\n\n")
        else:
            f.write("(aucun appel ZonePoint(lat, lon[, alt]) avec des coordonnées "
                    "valides n'a été trouvé dans le code décompilé)\n")
            f.write("Note : certaines cartouches purement virtuelles (puzzles, jeux "
                    "sans lien avec un lieu réel) ne définissent aucune zone GPS.\n")

    # ---- écriture inventaire.txt ----
    inventaire_path = os.path.join(output_dir, "inventaire.txt")
    with open(inventaire_path, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("INVENTAIRE (OBJETS ZITEM) DÉTECTÉS DANS LA CARTOUCHE\n")
        f.write("=" * 70 + "\n\n")
        f.write(
            "Note : une cartouche Wherigo ne déclare presque jamais l'emplacement\n"
            "initial d'un objet de façon statique. Le placement se fait presque\n"
            "toujours dynamiquement via des appels :MoveTo(cible) dans le code, en\n"
            "général au sein d'un scénario (ex: après une énigme résolue). La\n"
            "colonne \"Déplacements trouvés\" liste donc TOUTES les destinations\n"
            "possibles repérées dans le code pour un objet, pas une position figée.\n\n"
        )
        f.write(f"Objets trouvés : {len(inventory_items)}\n")
        f.write("-" * 70 + "\n")
        if inventory_items:
            for idx, it in enumerate(inventory_items, start=1):
                f.write(f"#{idx} - {it['variable']}\n")
                f.write(f"     Nom               : {it['name']}\n")
                if it["description"]:
                    f.write(f"     Description       : {it['description']}\n")
                if it["movements"]:
                    f.write(f"     Déplacements trouvés : {', '.join(it['movements'])}\n")
                else:
                    f.write("     Déplacements trouvés : (aucun trouvé statiquement)\n")
                f.write("\n")
        else:
            f.write("(aucun objet ZItem trouvé dans le code décompilé)\n")

    logger.info("\nTerminé.")
    logger.info(f"  - Métadonnées, texte en clair et résultats de recherche : {texte_clair_path}")
    logger.info(f"  - Code Lua complet (annoté)                             : {code_lua_path}")
    logger.info(f"  - Waypoints GPS détectés                                : {waypoints_path}")
    logger.info(f"  - Inventaire (objets)                                   : {inventaire_path}")
    logger.info(f"  - Bytecode Lua brut                                     : {luac_path}")
    logger.info(f"  - Journal détaillé (log)                                : {log_path}")
    if media_files:
        logger.info(f"  - {len(media_files)} fichiers médias extraits dans   : {media_dir}/")

    # Table de waypoints structurée pour un appelant programmatique (GUI) :
    # inclut la position de départ de l'en-tête en première ligne si valide.
    waypoints_table = []
    if starting_location:
        waypoints_table.append({
            "line": "-", "label": "(en-tête cartouche)",
            "name": "Position de départ (StartingLocation)",
            "lat": starting_location["lat"], "lon": starting_location["lon"],
            "alt": starting_location["alt"],
        })
    waypoints_table.extend(waypoints)

    return {
        "output_dir": output_dir,
        "texte_clair_path": texte_clair_path,
        "texte_clair_content": texte_clair_content,
        "code_lua_path": code_lua_path,
        "waypoints_path": waypoints_path,
        "waypoints_table": waypoints_table,
        "inventaire_path": inventaire_path,
        "inventory_items": inventory_items,
        "luac_path": luac_path,
        "log_path": log_path,
        "media_dir": media_dir,
        "nb_media": len(media_files),
        "nb_waypoints": len(waypoints),
        "nb_items": len(inventory_items),
        "nb_decoded": len(decoded_calls) + len(recovered_hidden_texts),
        "decompiled": bool(lua_source),
        "keywords_list": keywords_list,
    }


def main():
    """Point d'entrée en ligne de commande : lit les arguments puis
    délègue tout le travail à run_analysis()."""
    parser = argparse.ArgumentParser(
        description="Décompile et analyse un fichier cartouche Wherigo (.gwc)."
    )
    parser.add_argument("gwc_file", help="Chemin du fichier .gwc à analyser")
    parser.add_argument("--output-dir", help="Dossier de sortie (créé si besoin)")
    parser.add_argument("--unluac", help="Chemin explicite vers unluac.jar")
    parser.add_argument(
        "--keywords", default="",
        help="Liste de mots-clés à rechercher, séparés par des virgules "
             "(ex: --keywords \"passeport,visa,cyclope\")",
    )
    parser.add_argument(
        "--media", action="store_true",
        help="Extrait aussi les fichiers médias (images, sons...) de la cartouche",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.gwc_file):
        print(f"Fichier introuvable : {args.gwc_file}", file=sys.stderr)
        sys.exit(1)

    run_analysis(
        args.gwc_file,
        output_dir=args.output_dir,
        unluac_path=args.unluac,
        keywords=args.keywords,
        media=args.media,
    )


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("\n" + "=" * 70)
        print("UNE ERREUR EST SURVENUE :")
        print("=" * 70)
        if logger.handlers:
            # logger.exception écrit la trace complète dans la console ET
            # dans log.txt (si setup_logging a déjà été appelé).
            logger.exception("Erreur fatale")
        else:
            import traceback
            traceback.print_exc()
    finally:
        # Empêche la fenêtre de se fermer immédiatement si le script est
        # lancé en double-cliquant dessus (notamment sous Windows), pour
        # laisser le temps de lire les messages affichés ci-dessus.
        try:
            input("\nAppuyez sur Entrée pour fermer cette fenêtre...")
        except EOFError:
            pass
