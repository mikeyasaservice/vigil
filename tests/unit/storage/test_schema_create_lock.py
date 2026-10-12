from unittest.mock import MagicMock, patch

from core.storage.connection import DatabaseManager
from core.storage.models import Base


def _manager_with_engine(dialect: str):
    engine = MagicMock()
    engine.dialect.name = dialect
    connection = engine.begin.return_value.__enter__.return_value
    manager = DatabaseManager.__new__(DatabaseManager)
    manager._engine = engine
    return manager, connection


def test_postgres_schema_creation_is_serialized_by_transaction_lock():
    manager, connection = _manager_with_engine("postgresql")
    with patch.object(Base.metadata, "create_all") as create_all:
        manager.create_tables()

    statement = str(connection.execute.call_args.args[0])
    assert "pg_advisory_xact_lock" in statement
    create_all.assert_called_once_with(connection)


def test_non_postgres_schema_creation_does_not_issue_postgres_lock():
    manager, connection = _manager_with_engine("sqlite")
    with patch.object(Base.metadata, "create_all") as create_all:
        manager.create_tables()

    connection.execute.assert_not_called()
    create_all.assert_called_once_with(connection)
