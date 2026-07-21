"""
===========================================================
AI Digital Forensics Assistant
Hybrid RAG Engine
===========================================================
"""

import re
from pathlib import Path

from langchain_chroma import Chroma
from langchain_ollama import ChatOllama, OllamaEmbeddings


class DigitalForensicsAssistant:

    def __init__(self, model_name="llama3.2:1b"):

        print(f"\nInitializing AI Digital Forensics Assistant with model {model_name}...\n")

        self.embedding = OllamaEmbeddings(
            model="nomic-embed-text"
        )

        self.db = Chroma(
            persist_directory=str(
                Path(__file__).resolve().parent.parent
                / "VectorDB"
            ),
            embedding_function=self.embedding
        )

        self.llm = ChatOllama(
            model=model_name,
            temperature=0
        )

        print("[OK] Embedding Model Loaded")
        print("[OK] ChromaDB Connected")
        print(f"[OK] LLM {model_name} Ready\n")

    def detect_filename(self, question):

        question = question.lower()

        evidence_dir = Path(__file__).resolve().parent.parent / "Evidence"
        if not evidence_dir.exists():
            return None

        for file in evidence_dir.iterdir():
            if file.is_file():
                filename = file.name.lower()
                # Check for exact filename match (e.g. "active_directory.log")
                if filename in question:
                    return file.name
                
                # Check for human-readable aliases (e.g. "active directory log" -> "active_directory.log")
                base_name = file.stem.lower()
                clean_name = base_name.replace("_", " ").replace("-", " ")
                
                if clean_name in question or base_name in question:
                    return file.name

        return None

    def ask(self, question):

        filename = self.detect_filename(question)

        # Check if query is a synthesis/report query
        synthesis_keywords = ["report", "summary", "summarize", "timeline", "what happened", "overview", "incident", "verify", "check", "analyze"]
        is_synthesis = any(kw in question.lower() for kw in synthesis_keywords)

        print("=" * 70)
        print("Question :", question)

        if filename:

            print("Mode     : Metadata Filter Search")
            print("Filename :", filename)

            try:

                docs = self.db.similarity_search(
                    question,
                    k=4,
                    filter={
                        "filename": filename
                    }
                )

                docs_scores = [(doc, 1.0) for doc in docs]

            except Exception as e:

                print("Metadata filter not supported.")
                print(e)

                docs_scores = self.db.similarity_search_with_relevance_scores(
                    filename,
                    k=2
                )

        elif is_synthesis:

            print("Mode     : Global Synthesis Search")

            try:
                # Retrieve the first chunk of all files to construct the summary
                docs = self.db.similarity_search(
                    "incident evidence summary",
                    k=10,
                    filter={
                        "chunk": 1
                    }
                )
                docs_scores = [(doc, 1.0) for doc in docs]
            except Exception as e:
                print("Global synthesis filter failed, falling back to semantic search.")
                print(e)
                docs_scores = self.db.similarity_search_with_relevance_scores(question, k=4)

        else:

            print("Mode : Semantic Search")

            docs_scores = self.db.similarity_search_with_relevance_scores(
                question,
                k=4
            )

        context = ""
        sources = []
        confidence_scores = []

        for doc, score in docs_scores:

            source = doc.metadata.get(
                "filename",
                doc.metadata.get(
                    "source",
                    "Unknown"
                )
            )

            context += f"""
==================================================
SOURCE FILE

{source}

--------------------------------------------------

CONTENT

{doc.page_content}

"""

            sources.append(source)
            confidence_scores.append(score)

        if filename or is_synthesis:

            confidence = "High"

        else:

            if confidence_scores:

                avg = sum(confidence_scores) / len(confidence_scores)

            else:

                avg = 0

            if avg >= 0.80:

                confidence = "High"

            elif avg >= 0.60:

                confidence = "Medium"

            else:

                confidence = "Low"

        prompt = f"""
You are a Senior Digital Forensics Investigator.

You are assisting a Security Operations Center (SOC).

Rules

1. Answer ONLY using the supplied evidence.

2. Never invent information.

3. If evidence is insufficient, clearly say so.

4. Mention filenames whenever referring to evidence.

5. Use professional digital forensic terminology.

6. Do not use outside knowledge.

==================================================
Evidence
==================================================

{context}

==================================================
Investigator Question
==================================================

{question}

==================================================
Return your answer EXACTLY in this format

Executive Summary

Key Findings

Evidence Used

Recommendations

Confidence Level
==================================================
"""

        print("Running LLM...")
        response = self.llm.invoke(prompt)
        print("Completed.\n")

        return (
            response.content,
            list(dict.fromkeys(sources)),
            confidence
        )
