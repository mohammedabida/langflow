from __future__ import annotations
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from langflow.api.utils import  DbSession
from langflow.services.database.models.flows_share.model import FlowShare, FlowShareCreate, FlowShareRead
 
router = APIRouter(prefix="/flows_share", tags=["Flows Share"])
 
 
@router.post("/", response_model=FlowShareRead, status_code=201)
async def create_flow_share(
    *,
    session: DbSession,
    flow_share: FlowShareCreate,
):
    """Create a new flow share."""
    try:
        db_flow_share = FlowShare.from_orm(flow_share)
        db_flow_share.created_at = datetime.now(timezone.utc)
        session.add(db_flow_share)
        await session.commit()
        await session.refresh(db_flow_share)
        return db_flow_share
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e