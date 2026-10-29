
from fastapi import FastAPI

app = FastAPI(
    title="GENESIS",
    description=(
        "Genomic Information Encryption "
        "and Selective Information Sharing"
    ),
    version="0.1.0",
)


@app.get("/")
def home():
    return {
        "project": "GENESIS",
        "status": "running",
        "message": "Genomic privacy API is online.",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}
