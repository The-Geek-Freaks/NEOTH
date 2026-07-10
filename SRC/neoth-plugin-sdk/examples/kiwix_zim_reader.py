"""
NEOTH Skill Plugin: Kiwix ZIM Reader
Dieses Plugin ermöglicht NEOTH den direkten, extrem schnellen Zugriff auf lokale .zim Dateien 
(Offline Wikipedia, Wikibooks, Wiktionary) für den RAG-Context, ohne externe APIs zu belasten.

Requirements:
pip install libzim bs4
"""

from libzim.reader import Archive
from libzim.search import Query, Searcher
from bs4 import BeautifulSoup
import os

class KiwixReaderSkill:
    def __init__(self, zim_path: str):
        if not os.path.exists(zim_path):
            raise FileNotFoundError(f"ZIM Datei nicht gefunden: {zim_path}")
        self.zim = Archive(zim_path)
        self.searcher = Searcher(self.zim)
        
    def search_article(self, query: str, top_k: int = 3) -> list[dict]:
        """Sucht nach Artikeln in der ZIM Datei."""
        q = Query().set_query(query)
        results = self.searcher.search(q)
        
        articles = []
        # Get top_k results
        for i, res in enumerate(results):
            if i >= top_k:
                break
            # In neueren libzim Versionen gibt der iterator SearchResult objekte zurück
            entry = self.zim.get_entry_by_path(res.path)
            articles.append({
                "title": entry.get_item().title,
                "path": entry.get_item().path
            })
        return articles

    def read_article_content(self, path: str) -> str:
        """Liest den HTML-Content eines Artikels und konvertiert ihn zu reinem Text für LLM-Context."""
        entry = self.zim.get_entry_by_path(path)
        item = entry.get_item()
        html_content = item.content.tobytes().decode('utf-8', errors='ignore')
        
        # Parse HTML to clean text
        soup = BeautifulSoup(html_content, "html.parser")
        # Remove scripts and styles
        for script in soup(["script", "style", "nav", "footer"]):
            script.extract()
            
        text = soup.get_text(separator=' ', strip=True)
        return text

# Beispiel-Nutzung für NEOTH Plugin-Host:
if __name__ == "__main__":
    # skill = KiwixReaderSkill("/path/to/wikipedia_de_all_maxi.zim")
    # results = skill.search_article("Thermodynamik")
    # if results:
    #     text = skill.read_article_content(results[0]['path'])
    #     print(text[:500])
    pass
