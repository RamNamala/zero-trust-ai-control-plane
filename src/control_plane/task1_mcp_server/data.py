"""Deterministic fixture customers and the pure tool implementations.

Everything here is deterministic (no clocks, no randomness) so tests and the e2e demo can
assert exact outputs, and a retried refund produces the same ``refund_id`` - the closest a
mock gets to an idempotency key.
"""

from __future__ import annotations

import hashlib
from typing import Any

_CUSTOMERS: dict[str, dict[str, Any]] = {
    "CUST-10042": {
        "customer_id": "CUST-10042",
        "name": "Sarah Connor",
        "email": "sarah.connor@cyberdyne.io",
        "ssn": "999-01-4242",
        "tier": "gold",
        "balance": 1250.00,
        "last_orders": [
            {"order_id": "ORD-77001", "amount": 129.99, "status": "delivered"},
            {"order_id": "ORD-77015", "amount": 54.50, "status": "delivered"},
            {"order_id": "ORD-77102", "amount": 310.00, "status": "shipped"},
        ],
    },
    "CUST-20017": {
        "customer_id": "CUST-20017",
        "name": "Miles Dyson",
        "email": "m.dyson@cyberdyne.io",
        "ssn": "999-02-1717",
        "tier": "silver",
        "balance": 420.00,
        "last_orders": [
            {"order_id": "ORD-80311", "amount": 89.00, "status": "delivered"},
            {"order_id": "ORD-80344", "amount": 12.75, "status": "returned"},
            {"order_id": "ORD-80390", "amount": 230.40, "status": "processing"},
        ],
    },
    "CUST-30555": {
        "customer_id": "CUST-30555",
        "name": "John Connor",
        "email": "john.connor@resistance.net",
        "ssn": "999-03-0555",
        "tier": "bronze",
        "balance": 35.00,
        "last_orders": [
            {"order_id": "ORD-90001", "amount": 15.00, "status": "delivered"},
            {"order_id": "ORD-90002", "amount": 20.00, "status": "delivered"},
            {"order_id": "ORD-90003", "amount": 9.99, "status": "cancelled"},
        ],
    },
}


class CustomerNotFoundError(LookupError):
    pass


class RefundRejectedError(ValueError):
    pass


def get_customer(customer_id: str) -> dict[str, Any] | None:
    record = _CUSTOMERS.get(customer_id)
    return None if record is None else _deep_copy(record)


def make_refund_id(customer_id: str, amount: float, reason: str) -> str:
    digest = hashlib.sha256(f"{customer_id}|{amount:.2f}|{reason}".encode()).hexdigest()
    return f"RF-{digest[:10]}"


def get_customer_record(customer_id: str) -> dict[str, Any]:
    record = get_customer(customer_id)
    if record is None:
        raise CustomerNotFoundError(customer_id)
    return record


def trigger_refund(customer_id: str, amount: float, reason: str) -> dict[str, Any]:
    record = get_customer(customer_id)
    if record is None:
        raise CustomerNotFoundError(customer_id)
    if amount > record["balance"]:
        raise RefundRejectedError("amount exceeds refundable balance")
    return {
        "refund_id": make_refund_id(customer_id, amount, reason),
        "customer_id": customer_id,
        "amount": round(amount, 2),
        "status": "queued",
    }


def _deep_copy(record: dict[str, Any]) -> dict[str, Any]:
    """Callers get their own copy so nothing can mutate the fixtures between calls."""
    copy = dict(record)
    copy["last_orders"] = [dict(order) for order in record["last_orders"]]
    return copy
