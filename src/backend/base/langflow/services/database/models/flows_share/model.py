from typing import Optional, List
from uuid import UUID, uuid4
 
from sqlalchemy import Column, JSON
from sqlmodel import Field, SQLModel
 
class FlowShareBase(SQLModel):
    shared_with: List[UUID] = Field(default_factory=list, sa_column=Column(JSON), description="List of User IDs of the recipients")
    shared_by: UUID = Field(index=True, description="User ID of the sharer")
    flow_id: UUID = Field(index=True, description="ID of the shared flow")
    def __init__(self, **data):
        if "shared_with" in data:
            data["shared_with"] = [str(uuid) for uuid in data["shared_with"]]
        super().__init__(**data)
 
class FlowShare(FlowShareBase, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
 
class FlowShareCreate(FlowShareBase):
    pass
 
class FlowShareRead(FlowShareBase):
    id: UUID
 
class FlowShareUpdate(SQLModel):
    message: Optional[str] = None