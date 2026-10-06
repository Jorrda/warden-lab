"""Sign-in against the identity provider and the service token the scheduler uses."""
import requests

IDP_URL = "https://idp.fleetline.example/oauth/token"
# The scheduler authenticates with a long-lived token minted for the portal service account.
SERVICE_JWT = "eyJ8yoNa2WOSH8qwyQRokfV.eyJd6-Aq347r-o_46sTWleLej-9cPfw0gB2e4Eyz66m.nxaVAi7hykxYBy-GuNWhMrHKuLIzafLFaj4lai-OSsW"


def service_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {SERVICE_JWT}"}


def exchange_code(code: str) -> dict:
    response = requests.post(IDP_URL, data={"code": code, "grant_type": "authorization_code"}, timeout=10)
    response.raise_for_status()
    return response.json()
