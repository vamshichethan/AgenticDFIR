"""
===========================================================
Load and Split Digital Forensic Evidence
===========================================================
"""

from pathlib import Path

from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter


def load_documents():

    evidence_path = (
        Path(__file__).resolve().parent.parent
        / "Evidence"
    )

    documents = []

    print("\nLoading Evidence...\n")

    for file in sorted(evidence_path.iterdir()):

        if not file.is_file():
            continue

        with open(file, "r", encoding="utf-8") as f:

            text = f.read()

        document = Document(

            page_content=text,

            metadata={

                "source": file.name,

                "filename": file.name,

                "extension": file.suffix.lower(),

                "filepath": str(file),

                "filesize": file.stat().st_size

            }

        )

        documents.append(document)

        print(f"Loaded : {file.name}")

    splitter = RecursiveCharacterTextSplitter(

        chunk_size=700,

        chunk_overlap=150

    )

    chunks = splitter.split_documents(documents)

    ###########################################################
    # Add Chunk Metadata
    ###########################################################

    counter = {}

    for chunk in chunks:

        filename = chunk.metadata["filename"]

        counter[filename] = counter.get(filename, 0) + 1

        chunk.metadata["chunk"] = counter[filename]

    total = {}

    for chunk in chunks:

        filename = chunk.metadata["filename"]

        total[filename] = total.get(filename, 0) + 1

    for chunk in chunks:

        filename = chunk.metadata["filename"]

        chunk.metadata["total_chunks"] = total[filename]

    ###########################################################

    print("\nChunk Statistics")
    print("---------------------------------------")
    print("Original Documents :", len(documents))
    print("Chunks Created     :", len(chunks))
    print("---------------------------------------")

    return chunks
