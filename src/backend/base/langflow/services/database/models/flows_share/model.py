from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import Column, Text
from sqlmodel import Field, SQLModel

class FlowShareBase(SQLModel):
    shared_with: str = Field(index=True, description="Email or identifier of the recipient")
    shared_by: str = Field(index=True, description="Email or identifier of the sharer")
    flow_id: UUID = Field(index=True, description="ID of the shared flow")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Timestamp when the flow was shared")
    message: Optional[str] = Field(default=None, sa_column=Column(Text), description="Optional message with the share")

class FlowShare(FlowShareBase, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)

class FlowShareCreate(FlowShareBase):
    pass

class FlowShareRead(FlowShareBase):
    id: UUID
