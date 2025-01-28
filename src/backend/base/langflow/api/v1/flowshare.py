from __future__ import annotations
from fastapi import APIRouter, HTTPException
from langflow.api.utils import DbSession
from langflow.services.database.models.flows_share.model import FlowShare, FlowShareCreate, FlowShareRead
from langflow.services.database.models.flow import Flow  
from langflow.api.utils import CurrentActiveUser
from sqlmodel import select
from typing import List
 
router = APIRouter(prefix="/flows_share", tags=["Flows Share"])
 
@router.post("/", response_model=List[FlowShareRead], status_code=201)
async def create_flow_share(
    *,
    session: DbSession,
    flow_share: FlowShareCreate,
    current_user: CurrentActiveUser,
):
    """Create a new flow share for multiple recipients."""
 
    db_flow = await session.exec(select(Flow).where(Flow.id == flow_share.flow_id).where(Flow.user_id == current_user.id))
    if not db_flow:
        raise HTTPException(status_code=403, detail="You do not have permission to share this flow.")
 
    try:
       
        shared_flows = []
        for recipient_id in flow_share.shared_with:
            db_flow_share = FlowShare(
                shared_with=[str(recipient_id)],  
                shared_by=current_user.id,
                flow_id=flow_share.flow_id,
            )
            session.add(db_flow_share)
            shared_flows.append(db_flow_share)
 
        await session.commit()
        for db_flow_share in shared_flows:
            await session.refresh(db_flow_share)
 
        return shared_flows
 
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e