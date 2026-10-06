import stripe

from app import payments

# Test mode only: sk_test keys cannot move money.
STRIPE_TEST = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"


def test_charge_returns_an_intent_id(monkeypatch):
    monkeypatch.setattr(stripe.PaymentIntent, "create", lambda **kwargs: type("Intent", (), {"id": "pi_1"})())
    assert payments.charge("cus_1", 1000) == "pi_1"
