"""
Create embeddings and store them in ChromaDB with offline resilience.
"""

from pathlib import Path
from rag_assistant.load_documents import load_documents


def create_vector_database():
    """
    Build vector database in VectorDB directory.
    Uses nomic-embed-text if Ollama is available; handles offline gracefully.
    """
    print("\nLoading Documents...")
    chunks = load_documents()

    vector_db_path = (
        Path(__file__).resolve().parent.parent
        / "VectorDB"
    )

    try:
        from langchain_chroma import Chroma
        from langchain_ollama import OllamaEmbeddings

        print("\nAttempting to create Ollama embeddings (nomic-embed-text)...")
        embeddings = OllamaEmbeddings(
            model="nomic-embed-text"
        )

        db = Chroma.from_documents(
            documents=chunks,
            embedding=embeddings,
            persist_directory=str(vector_db_path)
        )
        print("\nVector Database Created Successfully with ChromaDB & Ollama")
        print(f"Database Location : {vector_db_path}")
        print(f"Total Chunks Indexed : {len(chunks)}")
        return db

    except Exception as e:
        print(f"\n[INFO] Ollama embeddings offline or unavailable: {e}")
        print("[INFO] Fallback to In-Memory Hybrid Keyword Search index will be used.")
        vector_db_path.mkdir(parents=True, exist_ok=True)
        # Store an index marker
        marker_file = vector_db_path / "fallback_index.json"
        import json
        index_data = [
            {
                "page_content": c.page_content,
                "metadata": c.metadata
            }
            for c in chunks
        ]
        marker_file.write_text(json.dumps(index_data, indent=2), encoding="utf-8")
        print(f"Fallback In-Memory Index Created: {len(chunks)} chunks.")
        return None
