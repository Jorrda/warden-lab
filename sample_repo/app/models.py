"""Portal models."""
from dataclasses import dataclass


@dataclass
class Shipment:
    id: int
    customer_id: int
    status: str


@dataclass
class Driver:
    id: int
    name: str
    vehicle: str
