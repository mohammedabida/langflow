"""Flow Database update

Revision ID: 5d090e9c10d9
Revises: e3162c1804e6
Create Date: 2025-01-28 03:02:22.302010

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel
from sqlalchemy.engine.reflection import Inspector
from langflow.utils import migration


# revision identifiers, used by Alembic.
revision: str = '5d090e9c10d9'
down_revision: Union[str, None] = 'e3162c1804e6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('flow', schema=None) as batch_op:
        batch_op.add_column(sa.Column('published', sa.Boolean(), nullable=True))

    # ### end Alembic commands ###


def downgrade() -> None:
    conn = op.get_bind()
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('flow', schema=None) as batch_op:
        batch_op.drop_column('published')

    # ### end Alembic commands ###
