"""Strict input models for the Task 1 tools.

The advertised ``inputSchema`` is generated from these models, so the contract a client sees
and the validator the server runs cannot drift apart. Strict mode is deliberate: an agent that
sends ``"50"`` or ``true`` for an amount has a bug, and coercing it would hide that bug behind a
real refund. A JSON integer is still accepted for a float field (``50`` is a legitimate refund).
"""

from __future__ import annotations

from decimal import Decimal
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

# [0-9], not \d: Python's \d also matches Arabic-Indic and other Unicode digits.
CustomerId = Annotated[str, StringConstraints(pattern=r"^CUST-[0-9]{5}$")]


class GetCustomerRecordInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    customer_id: CustomerId


class TriggerRefundInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    customer_id: CustomerId
    amount: Annotated[float, Field(gt=0, le=10_000, allow_inf_nan=False)]
    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=10, max_length=500)]

    @field_validator("amount")
    @classmethod
    def _at_most_two_decimals(cls, value: float) -> float:
        # str() gives the shortest round-tripping repr, so 10.1 stays "10.1" rather than the
        # binary expansion; exponent < -2 means fractional cents.
        exponent = Decimal(str(value)).as_tuple().exponent
        if isinstance(exponent, int) and exponent < -2:
            raise ValueError("amount must have at most 2 decimal places")
        return value


TOOL_INPUT_MODELS: dict[str, type[BaseModel]] = {
    "get_customer_record": GetCustomerRecordInput,
    "trigger_refund": TriggerRefundInput,
}

TOOL_DESCRIPTIONS: dict[str, str] = {
    "get_customer_record": "Fetch a customer record by ID (format CUST-12345).",
    "trigger_refund": (
        "Queue a refund for a customer. Amount in account currency, > 0, <= 10000, "
        "at most 2 decimal places; reason 10-500 characters."
    ),
}


def tool_input_schema(model: type[BaseModel]) -> dict[str, Any]:
    """``extra="forbid"`` already emits ``additionalProperties: false``; set it explicitly anyway
    so the advertised contract doesn't depend on a Pydantic implementation detail."""
    schema = model.model_json_schema()
    schema["additionalProperties"] = False
    return schema
