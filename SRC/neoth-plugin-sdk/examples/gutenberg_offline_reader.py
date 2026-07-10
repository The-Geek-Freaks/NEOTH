"""
NEOTH Skill Plugin: Project Gutenberg Offline Library
Durchsucht einen per rsync gespiegelten lokalen Project Gutenberg Ordner
und lädt ausgewählte Public-Domain Bücher als puren Text in den LLM-Context.
"""
import os
import glob

class GutenbergOfflineSkill:
    def __init__(self, mirror_path: str):
        if not os.path.exists(mirror_path):
            raise FileNotFoundError(f"Gutenberg Mirror nicht gefunden: {mirror_path}")
        self.mirror_path = mirror_path

    def find_book_by_id(self, ebook_id: str) -> str:
        """Findet die .txt Datei eines Buches anhand der Gutenberg-ID (z.B. '1342' für Pride and Prejudice)."""
        # Gutenberg Struktur: /1/3/4/1342/1342-0.txt
        path_parts = list(ebook_id)[:-1]
        dir_path = os.path.join(self.mirror_path, *path_parts, ebook_id)
        
        search_pattern = os.path.join(dir_path, "*.txt")
        files = glob.glob(search_pattern)
        
        if files:
            return files[0]
        return ""

    def read_book_excerpt(self, ebook_id: str, start_line: int = 0, num_lines: int = 1000) -> str:
        """Liest einen Ausschnitt aus einem Offline-Buch für den Agenten."""
        file_path = self.find_book_by_id(ebook_id)
        if not file_path:
            return "Buch nicht im lokalen Mirror gefunden."
            
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
        excerpt = "".join(lines[start_line:start_line+num_lines])
        return excerpt

if __name__ == "__main__":
    # skill = GutenbergOfflineSkill("/path/to/gutenberg/mirror")
    # text = skill.read_book_excerpt("1342", start_line=500, num_lines=100)
    # print(text)
    pass
