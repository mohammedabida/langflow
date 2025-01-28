from typing import List
from .model import FlowShare

def get_shares_by_user(shared_by: str, shares: List[FlowShare]):
    """Get all flows shared by a specific user."""
    return [share for share in shares if share.shared_by == shared_by]

def get_shares_with_user(shared_with: str, shares: List[FlowShare]):
    """Get all flows shared with a specific user."""
    return [share for share in shares if share.shared_with == shared_with]

def filter_shares_by_tag(shares: List[FlowShare], tag: str):
    """Filter shared flows by tag."""
    return [share for share in shares if tag in share.message]