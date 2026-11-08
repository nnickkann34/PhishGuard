"""
Check history, stored in SQLite through SQLAlchemy.

Every query here goes through the ORM, which sends user input to the
database as bound parameters, never as part of the SQL text. That is the
defence against SQL injection (section 2.7).

search_history_insecure() exists only to demonstrate the attack in the
video. It is used only when PG_INSECURE_SQL_DEMO=true and is clearly
marked; it must never be enabled in normal use.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    DateTime, Float, Integer, String, Text, create_engine, delete, func, select, text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class Check(Base):
    __tablename__ = "checks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(36), index=True)
    url: Mapped[str] = mapped_column(Text)
    verdict: Mapped[str] = mapped_column(String(16))
    malicious_probability: Mapped[float] = mapped_column(Float)
    confidence: Mapped[float] = mapped_column(Float)
    warnings: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


def make_session_factory(database_url: str) -> sessionmaker[Session]:
    if database_url.startswith("sqlite:///"):
        from pathlib import Path
        Path(database_url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(
        database_url,
        connect_args={"check_same_thread": False} if database_url.startswith("sqlite") else {},
    )
    Base.metadata.create_all(engine)
    return sessionmaker(engine, expire_on_commit=False)


def add_check(db: Session, session_id: str, url: str, verdict: str,
              malicious_probability: float, confidence: float, warnings: list[str]) -> Check:
    row = Check(
        session_id=session_id, url=url, verdict=verdict,
        malicious_probability=malicious_probability, confidence=confidence,
        warnings="\n".join(warnings),
    )
    db.add(row)
    db.commit()
    return row


def search_history(db: Session, session_id: str, query: str | None, limit: int) -> list[Check]:
    """Safe: session_id and query are bound parameters."""
    stmt = select(Check).where(Check.session_id == session_id)
    if query:
        stmt = stmt.where(Check.url.contains(query, autoescape=True))
    stmt = stmt.order_by(Check.id.desc()).limit(limit)
    return list(db.scalars(stmt))


def search_history_insecure(db: Session, session_id: str, query: str | None, limit: int) -> list[Check]:
    """
    DEMO ONLY - VULNERABLE TO SQL INJECTION.
    Builds the SQL by pasting user input into the string, so input such as
    ' OR '1'='1 changes the query and returns every user's history.
    """
    sql = f"SELECT id FROM checks WHERE session_id = '{session_id}'"
    if query:
        sql += f" AND url LIKE '%{query}%'"
    sql += f" ORDER BY id DESC LIMIT {int(limit)}"
    ids = [r[0] for r in db.execute(text(sql))]
    if not ids:
        return []
    return list(db.scalars(select(Check).where(Check.id.in_(ids)).order_by(Check.id.desc())))


def clear_history(db: Session, session_id: str) -> int:
    result = db.execute(delete(Check).where(Check.session_id == session_id))
    db.commit()
    return result.rowcount or 0


def session_stats(db: Session, session_id: str) -> dict:
    rows = db.execute(
        select(Check.verdict, func.count(), func.avg(Check.confidence))
        .where(Check.session_id == session_id)
        .group_by(Check.verdict)
    ).all()
    counts = {"phishing": 0, "legitimate": 0}
    avg_conf = {"phishing": None, "legitimate": None}
    for verdict, count, avg in rows:
        counts[verdict] = count
        avg_conf[verdict] = round(float(avg), 4) if avg is not None else None
    return {"total": sum(counts.values()), "counts": counts, "average_confidence": avg_conf}
