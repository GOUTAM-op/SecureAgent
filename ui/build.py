"""Inline CSS + JS into a single self-contained ui/index.html."""
from pathlib import Path
src = Path(__file__).parent / "src"
html = (src / "template.html").read_text()
for key, name in (("/*__CSS__*/", "style.css"), ("/*__ENGINE__*/", "engine.js"), ("/*__APP__*/", "app.js")):
    html = html.replace(key, (src / name).read_text())
out = Path(__file__).parent / "index.html"
out.write_text(html)
print(f"wrote {out} ({len(html)/1024:.0f} KB)")
