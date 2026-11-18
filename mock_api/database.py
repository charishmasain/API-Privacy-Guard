"""
API PrivacyGuard - Mock API Environment
========================================
SQLite-backed data store for the local mock API.

This module is ISOLATED from the main application and is intended for
LOCAL DEVELOPMENT / TESTING ONLY. It seeds two synthetic users (Alice and
Bob) who each own a profile resource with sensitive personal data.

Alice owns resource id 101, Bob owns resource id 202.
"""
from __future__ import annotations

import os
from typing import Optional

from sqlalchemy import Column, Float, ForeignKey, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

MOCK_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mock_data.db")

Base = declarative_base()


class MockUser(Base):
    """A synthetic API user with a static bearer token."""

    __tablename__ = "mock_users"

    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False, unique=True)
    bearer_token = Column(String, nullable=False, unique=True)
    full_name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    phone = Column(String, nullable=False)
    date_of_birth = Column(String, nullable=False)
    address = Column(String, nullable=False)
    national_id = Column(String, nullable=False)
    salary = Column(Float, nullable=False)

    # The resource this user owns in the "profiles" store (101 for Alice, 202 for Bob)
    owned_resource_id = Column(Integer, ForeignKey("mock_resources.id"), nullable=True)

    owned_resource = relationship("MockResource", foreign_keys=[owned_resource_id])


class MockResource(Base):
    """An owned object (profile record) returned by the mock endpoints."""

    __tablename__ = "mock_resources"

    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, nullable=False)
    owner_username = Column(String, nullable=False)
    title = Column(String, nullable=False)
    description = Column(String, nullable=False)
    email = Column(String, nullable=False)
    phone = Column(String, nullable=False)
    address = Column(String, nullable=False)
    date_of_birth = Column(String, nullable=False)
    national_id = Column(String, nullable=False)
    credit_card = Column(String, nullable=False)


engine = create_engine(f"sqlite:///{MOCK_DB_PATH}", future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def _seed() -> None:
    """(Re)create the mock database with deterministic demo data."""
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

    session = SessionLocal()
    try:
        res_alice = MockResource(
            id=101,
            owner_id=1,
            owner_username="alice",
            title="Alice's Customer Profile",
            description="Premium tier account with billing details.",
            email="alice.johnson@example.com",
            phone="+1-555-010-1010",
            address="42 Maple Street, Springfield, IL 62701",
            date_of_birth="1988-04-12",
            national_id="SSN 123-45-6789",
            credit_card="4111 1111 1111 1111",
        )
        res_bob = MockResource(
            id=202,
            owner_id=2,
            owner_username="bob",
            title="Bob's Customer Profile",
            description="Standard tier account with billing details.",
            email="bob.smith@example.com",
            phone="+1-555-020-2020",
            address="7 Oak Avenue, Shelbyville, IL 62565",
            date_of_birth="1975-09-30",
            national_id="SSN 987-65-4321",
            credit_card="5500 0000 0000 0004",
        )
        alice = MockUser(
            id=1,
            username="alice",
            bearer_token="mock-token-alice-3f8a9c",
            full_name="Alice Johnson",
            email="alice.johnson@example.com",
            phone="+1-555-010-1010",
            date_of_birth="1988-04-12",
            address="42 Maple Street, Springfield, IL 62701",
            national_id="SSN 123-45-6789",
            salary=98000.0,
            owned_resource_id=101,
        )
        bob = MockUser(
            id=2,
            username="bob",
            bearer_token="mock-token-bob-77d1e0",
            full_name="Bob Smith",
            email="bob.smith@example.com",
            phone="+1-555-020-2020",
            date_of_birth="1975-09-30",
            address="7 Oak Avenue, Shelbyville, IL 62565",
            national_id="SSN 987-65-4321",
            salary=61000.0,
            owned_resource_id=202,
        )
        # A second shared resource so list endpoints have >1 row
        extra = MockResource(
            id=303,
            owner_id=1,
            owner_username="alice",
            title="Alice's Secondary Account",
            description="Secondary loyalty account.",
            email="alice.j@example.com",
            phone="+1-555-010-9999",
            address="42 Maple Street, Springfield, IL 62701",
            date_of_birth="1988-04-12",
            national_id="SSN 123-45-6789",
            credit_card="4111 1111 1111 1111",
        )
        session.add_all([res_alice, res_bob, alice, bob, extra])
        session.commit()
    finally:
        session.close()


def init_mock_db(force: bool = True) -> None:
    """Ensure the mock database exists. force=True reseeds deterministically."""
    if force or not os.path.exists(MOCK_DB_PATH):
        _seed()


def get_user_by_token(token: str) -> Optional[MockUser]:
    session = SessionLocal()
    try:
        return session.query(MockUser).filter(MockUser.bearer_token == token).first()
    finally:
        session.close()


def get_resource(res_id: int) -> Optional[MockResource]:
    session = SessionLocal()
    try:
        return session.query(MockResource).filter(MockResource.id == res_id).first()
    finally:
        session.close()


def list_resources_for_owner(owner_username: str) -> list[MockResource]:
    session = SessionLocal()
    try:
        return (
            session.query(MockResource)
            .filter(MockResource.owner_username == owner_username)
            .all()
        )
    finally:
        session.close()


if __name__ == "__main__":
    init_mock_db()
    print(f"Mock database initialised at: {MOCK_DB_PATH}")
