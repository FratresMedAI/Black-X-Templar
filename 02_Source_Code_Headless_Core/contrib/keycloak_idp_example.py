"""
contrib/keycloak_idp_example.py

Reference integration for Kinetic Hooks IdP actions using Keycloak Admin API.
This is an optional example for deployment teams; it is not imported by default.

Environment variables:
- KEYCLOAK_BASE_URL
- KEYCLOAK_REALM
- KEYCLOAK_CLIENT_ID
- KEYCLOAK_CLIENT_SECRET
"""

import os
import requests


class KeycloakIdP:
    def __init__(self):
        self.base_url = os.environ.get("KEYCLOAK_BASE_URL", "").rstrip("/")
        self.realm = os.environ.get("KEYCLOAK_REALM", "master")
        self.client_id = os.environ.get("KEYCLOAK_CLIENT_ID", "")
        self.client_secret = os.environ.get("KEYCLOAK_CLIENT_SECRET", "")

    def _token(self) -> str:
        if not (self.base_url and self.client_id and self.client_secret):
            raise ValueError("Keycloak config missing. Set KEYCLOAK_BASE_URL/CLIENT_ID/CLIENT_SECRET.")

        token_url = f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/token"
        resp = requests.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def revoke_user_sessions(self, user_id: str) -> int:
        """Invalidate all active sessions for a specific Keycloak user ID."""
        token = self._token()
        url = f"{self.base_url}/admin/realms/{self.realm}/users/{user_id}/logout"
        resp = requests.post(url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
        return resp.status_code

    def require_reauth(self, user_id: str) -> int:
        """
        Require re-auth by marking required action.
        Example uses UPDATE_PASSWORD as a concrete admin-enforced challenge.
        """
        token = self._token()
        url = f"{self.base_url}/admin/realms/{self.realm}/users/{user_id}"
        resp = requests.put(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json={"requiredActions": ["UPDATE_PASSWORD"]},
            timeout=10,
        )
        return resp.status_code


if __name__ == "__main__":
    print("Keycloak IdP example module. Import KeycloakIdP into your deployment glue code.")
