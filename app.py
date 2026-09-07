"""
Interface web (Streamlit) pour gwc_analyzer.
Remplace gwc_analyzer_gui.pyw — toute la logique reste dans gwc_analyzer.py,
inchangée.
"""
import os
import io
import re
import html
import zipfile
import tempfile
import subprocess

import streamlit as st

from gwc_analyzer import run_analysis, GPS_PATTERNS

IMAGE_EXTS = {"jpg", "jpeg", "png", "bmp", "gif"}
AUDIO_EXTS = {"mp3", "wav", "ogg"}

st.set_page_config(page_title="GWC Analyzer", page_icon="🧭", layout="wide")

st.title("🧭 GWC Analyzer")
st.caption("Décompilateur / analyseur de cartouches Wherigo (.gwc)")

# --- Localisation de Java ----------------------------------------------------
# gwc_analyzer.py appelle directement la commande "java" (recherchée dans le
# PATH). On utilise en priorité le JDK embarqué (package pip "jdk4py"), pour
# ne pas dépendre d'apt-get / packages.txt (dépôts Debian parfois
# indisponibles sur Streamlit Cloud) : on ajoute son dossier bin au PATH.
java_ok = False
java_error_detail = None
try:
    from jdk4py import JAVA
    # S'assurer que le binaire est exécutable (parfois perdu selon l'environnement
    # d'installation du wheel).
    try:
        os.chmod(JAVA, 0o755)
    except Exception:
        pass
    java_bin_dir = str(JAVA.parent)
    if java_bin_dir not in os.environ.get("PATH", ""):
        os.environ["PATH"] = java_bin_dir + os.pathsep + os.environ.get("PATH", "")
    result = subprocess.run(
        ["java", "-version"], capture_output=True, text=True
    )
    if result.returncode == 0:
        java_ok = True
    else:
        java_error_detail = f"code retour {result.returncode} — stderr: {result.stderr}"
except Exception as e:
    java_error_detail = f"{type(e).__name__}: {e}"

if not java_ok:
    st.warning(
        "⚠️ Java n'est pas détecté sur ce serveur. L'analyse fonctionnera "
        "partiellement (métadonnées + bytecode brut), mais sans décompilation "
        "du code Lua ni désobfuscation."
    )
    if java_error_detail:
        with st.expander("🔍 Détail technique (pour diagnostic)"):
            st.code(java_error_detail)

# --- Formulaire --------------------------------------------------------------
with st.sidebar:
    st.header("Paramètres")
    uploaded_file = st.file_uploader("Fichier cartouche (.gwc)", type=["gwc"])
    keywords = st.text_input(
        "Mots-clés à rechercher",
        placeholder="passeport, visa, indice",
        help="Séparés par des virgules",
    )
    extract_media = st.checkbox("Extraire les fichiers médias", value=False)
    launch = st.button("🚀 Lancer l'analyse", type="primary", disabled=uploaded_file is None)


def highlight_text(text, keywords_list):
    """Échappe le texte pour affichage HTML puis surligne :
    - en vert les coordonnées GPS détectées (mêmes motifs que gwc_analyzer)
    - en jaune les mots-clés recherchés (insensible à la casse)
    Les correspondances qui se chevauchent sont fusionnées, priorité aux
    motifs GPS (plus spécifiques), comme dans find_gps_matches.
    """
    spans = []  # (start, end, css_class)

    for pattern, _parser in GPS_PATTERNS:
        for m in pattern.finditer(text):
            start, end = m.span()
            if any(start < e and s < end for s, e, _ in spans):
                continue
            spans.append((start, end, "gps"))

    for kw in keywords_list:
        kw = kw.strip()
        if not kw:
            continue
        try:
            for m in re.finditer(re.escape(kw), text, re.IGNORECASE):
                start, end = m.span()
                if any(start < e and s < end for s, e, _ in spans):
                    continue
                spans.append((start, end, "kw"))
        except re.error:
            continue

    spans.sort(key=lambda s: s[0])

    out = []
    pos = 0
    for start, end, css in spans:
        if start < pos:
            continue
        out.append(html.escape(text[pos:start]))
        color = "#90EE90" if css == "gps" else "#FFEB3B"
        out.append(
            f'<mark style="background-color:{color};padding:0 2px;border-radius:3px;">'
            f"{html.escape(text[start:end])}</mark>"
        )
        pos = end
    out.append(html.escape(text[pos:]))
    return "".join(out)


# --- Lancement de l'analyse ---------------------------------------------------
if launch and uploaded_file is not None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        gwc_path = os.path.join(tmp_dir, uploaded_file.name)
        with open(gwc_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        output_dir = os.path.join(tmp_dir, "resultats")

        with st.spinner("Analyse en cours..."):
            try:
                result = run_analysis(
                    gwc_path,
                    output_dir=output_dir,
                    keywords=keywords,
                    media=extract_media,
                )
            except Exception as e:
                st.error(f"Erreur pendant l'analyse : {e}")
                st.stop()

        st.success("Analyse terminée !")

        # --- Résumé ------------------------------------------------------
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Waypoints trouvés", result["nb_waypoints"])
        c2.metric("Objets (inventaire)", result["nb_items"])
        c3.metric("Chaînes désobfusquées", result["nb_decoded"])
        c4.metric("Médias extraits", result["nb_media"])

        # --- Onglets -------------------------------------------------------
        tab_labels = ["📄 Texte clair", "📍 Waypoints", "🎒 Inventaire", "💾 Téléchargements"]
        if extract_media:
            tab_labels.insert(3, "🖼️ Médias")
        tabs = st.tabs(tab_labels)
        tab_texte, tab_wp, tab_inv = tabs[0], tabs[1], tabs[2]
        if extract_media:
            tab_media, tab_dl = tabs[3], tabs[4]
        else:
            tab_dl = tabs[3]

        with tab_texte:
            keywords_list = result.get("keywords_list", [])
            st.caption("🟢 Coordonnées GPS détectées   🟡 Mots-clés recherchés")
            highlighted = highlight_text(result["texte_clair_content"], keywords_list)
            st.markdown(
                f'<div style="white-space:pre-wrap;font-family:monospace;'
                f'font-size:0.85rem;max-height:600px;overflow-y:auto;'
                f'border:1px solid rgba(128,128,128,0.3);padding:12px;border-radius:6px;">'
                f"{highlighted}</div>",
                unsafe_allow_html=True,
            )

        with tab_wp:
            if result["waypoints_table"]:
                st.dataframe(result["waypoints_table"], use_container_width=True)
            else:
                st.info("Aucun waypoint détecté.")

        with tab_inv:
            if result["inventory_items"]:
                st.dataframe(result["inventory_items"], use_container_width=True)
            else:
                st.info("Aucun objet détecté.")

        if extract_media:
            with tab_media:
                media_dir = result.get("media_dir")
                if media_dir and os.path.isdir(media_dir):
                    all_files = sorted(os.listdir(media_dir))
                    images = [f for f in all_files if f.rsplit(".", 1)[-1].lower() in IMAGE_EXTS]
                    others = [f for f in all_files if f not in images]

                    if images:
                        st.subheader(f"Images ({len(images)})")
                        cols = st.columns(4)
                        for i, fname in enumerate(images):
                            fpath = os.path.join(media_dir, fname)
                            with cols[i % 4]:
                                st.image(fpath, caption=fname, use_container_width=True)
                                with open(fpath, "rb") as f:
                                    st.download_button(
                                        "⬇️", data=f.read(), file_name=fname,
                                        key=f"img_dl_{fname}",
                                    )
                    else:
                        st.info("Aucune image extraite.")

                    if others:
                        st.subheader(f"Autres fichiers ({len(others)})")
                        for fname in others:
                            fpath = os.path.join(media_dir, fname)
                            ext = fname.rsplit(".", 1)[-1].lower()
                            with open(fpath, "rb") as f:
                                data = f.read()
                            col_a, col_b = st.columns([3, 1])
                            with col_a:
                                st.write(f"🎵 {fname}" if ext in AUDIO_EXTS else f"📄 {fname}")
                                if ext in AUDIO_EXTS:
                                    st.audio(data)
                            with col_b:
                                st.download_button(
                                    "⬇️ Télécharger", data=data, file_name=fname,
                                    key=f"other_dl_{fname}",
                                )
                else:
                    st.info("Aucun média extrait.")

        with tab_dl:
            st.write("Télécharge tous les fichiers générés dans un seul zip :")

            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
                for root, _, files in os.walk(output_dir):
                    for name in files:
                        full_path = os.path.join(root, name)
                        arcname = os.path.relpath(full_path, output_dir)
                        zf.write(full_path, arcname)
            zip_buffer.seek(0)

            st.download_button(
                "⬇️ Télécharger tous les résultats (.zip)",
                data=zip_buffer,
                file_name=f"{os.path.splitext(uploaded_file.name)[0]}_analyse.zip",
                mime="application/zip",
            )

elif uploaded_file is None:
    st.info("👈 Choisis un fichier .gwc dans le menu de gauche pour commencer.")
