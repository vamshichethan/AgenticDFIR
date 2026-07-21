"""
Create embeddings and store them in ChromaDB
"""

from pathlib import Path

from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings

from rag_assistant.load_documents import load_documents


def create_vector_database():

    print("\nLoading Documents...")

    chunks = load_documents()

    print("\nCreating Embeddings...")

    embeddings = OllamaEmbeddings(
        model="nomic-embed-text"
    )

    vector_db_path = (
        Path(__file__).resolve().parent.parent
        / "VectorDB"
    )

    db = Chroma.from_documents(
        documents=chunks,
        embedding=embeddings,
        persist_directory=str(vector_db_path)
    )

    print("\nVector Database Created Successfully")

    print(f"Database Location : {vector_db_path}")

    print(f"Total Chunks Indexed : {len(chunks)}")

    return db
