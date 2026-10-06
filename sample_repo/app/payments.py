"""Card payments for customer invoices."""
import stripe

stripe.api_key = "sk_live_pKQdEk9AdhIH8SD56RK9vha7"


def charge(customer_id: str, amount_cents: int) -> str:
    intent = stripe.PaymentIntent.create(amount=amount_cents, currency="ils", customer=customer_id)
    return intent.id
