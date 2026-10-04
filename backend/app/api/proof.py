"""
Proofs of Fix API
Cryptographic SHA-256 Proof of Fix verification records.
"""
from fastapi import APIRouter, HTTPException, Query
from typing import Dict, Any
from ..database.repository import repo

router = APIRouter(tags=["Proofs"])

@router.get("/api/proofs")
def get_proofs(workspace_id: str = Query("ws_default_01")):
    return repo.get_proofs(workspace_id)

@router.get("/api/proofs/{proof_id}")
def get_proof(proof_id: str):
    proof = repo.get_proof(proof_id)
    if not proof:
        raise HTTPException(status_code=404, detail="Proof of fix certificate not found.")
    return proof
