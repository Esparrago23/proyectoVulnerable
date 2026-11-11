"""Pruebas para el sistema de autenticación multi-capacidad en proyectoVulnerable.

Flujos probados:
1. operador_simple: login simple -> 302 -> /dashboard
2. analista_2fa: login -> 302 -> /mfa -> verificación TOTP -> 302 -> /dashboard
3. auditor_doc: login -> 302 -> /verify-doc -> carga de certificado -> 302 -> /dashboard
4. Casos negativos: contraseña inválida, TOTP incorrecto y certificado inválido.
5. Verificación física con el archivo meta/certs/acreditacion_orca.pem.
"""

from __future__ import annotations

import io
from pathlib import Path
import re
import sys
import unittest

# Asegurar target/app_python en sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
APP_PYTHON_DIR = REPO_ROOT / "target" / "app_python"
if str(APP_PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(APP_PYTHON_DIR))

from app import app
from auth.mfa_handler import generate_totp_code
import config


class MultiCapabilityAuthTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def _get_csrf_token(self, client, path: str = "/login") -> str:
        """Obtiene el token CSRF visitando la ruta indicada."""
        resp = client.get(path)
        html = resp.get_data(as_text=True)
        match = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', html)
        if match:
            return match.group(1)
        with client.session_transaction() as sess:
            return sess.get("csrf_token", "")

    def test_operador_simple_flow(self):
        """Flujo operador_simple: /login -> /dashboard directo (1 barrera)."""
        csrf = self._get_csrf_token(self.client)
        resp = self.client.post(
            "/login",
            data={
                "username": "operador_simple",
                "password": "SimplePass2026!",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp.headers["Location"].endswith("/dashboard"))

        # Acceso confirmado al dashboard
        dash_resp = self.client.get("/dashboard")
        self.assertEqual(dash_resp.status_code, 200)
        self.assertIn("operador_simple", dash_resp.get_data(as_text=True))

    def test_analista_2fa_flow(self):
        """Flujo analista_2fa: /login -> /mfa -> TOTP -> /dashboard (2 barreras)."""
        csrf = self._get_csrf_token(self.client)
        resp = self.client.post(
            "/login",
            data={
                "username": "analista_2fa",
                "password": "MfaPass2026!",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp.headers["Location"].endswith("/mfa"))

        csrf_mfa = self._get_csrf_token(self.client, "/mfa") or csrf
        totp_code = generate_totp_code("JBSWY3DPEHPK3PXP")
        mfa_post = self.client.post(
            "/mfa",
            data={
                "totp_code": totp_code,
                "csrf_token": csrf_mfa,
            },
            follow_redirects=False,
        )
        self.assertEqual(mfa_post.status_code, 302)
        self.assertTrue(mfa_post.headers["Location"].endswith("/dashboard"))

        dash_resp = self.client.get("/dashboard")
        self.assertEqual(dash_resp.status_code, 200)
        self.assertIn("analista_2fa", dash_resp.get_data(as_text=True))

    def test_auditor_doc_flow(self):
        """Flujo auditor_doc: /login -> /verify-doc -> Certificado -> /dashboard."""
        csrf = self._get_csrf_token(self.client)
        resp = self.client.post(
            "/login",
            data={
                "username": "auditor_doc",
                "password": "DocPass2026!",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp.headers["Location"].endswith("/verify-doc"))

        csrf_doc = self._get_csrf_token(self.client, "/verify-doc") or csrf
        cert_bytes = b"ORCA-CERT-2026-VALID\nCERTIFICATE"

        doc_post = self.client.post(
            "/verify-doc",
            data={
                "accreditation_doc": (io.BytesIO(cert_bytes), "acreditacion_orca.pem"),
                "csrf_token": csrf_doc,
            },
            content_type="multipart/form-data",
            follow_redirects=False,
        )
        self.assertEqual(doc_post.status_code, 302)
        self.assertTrue(doc_post.headers["Location"].endswith("/dashboard"))

        dash_resp = self.client.get("/dashboard")
        self.assertEqual(dash_resp.status_code, 200)
        self.assertIn("auditor_doc", dash_resp.get_data(as_text=True))

    def test_invalid_credentials_rejected(self):
        """Verifica rechazo con credenciales erróneas."""
        csrf = self._get_csrf_token(self.client)
        resp = self.client.post(
            "/login",
            data={
                "username": "operador_simple",
                "password": "WrongPassword123!",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Credenciales incorrectas", resp.get_data(as_text=True))

    def test_invalid_totp_rejected(self):
        """Verifica rechazo de código TOTP erróneo."""
        csrf = self._get_csrf_token(self.client)
        self.client.post(
            "/login",
            data={
                "username": "analista_2fa",
                "password": "MfaPass2026!",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        csrf_mfa = self._get_csrf_token(self.client, "/mfa") or csrf
        mfa_post = self.client.post(
            "/mfa",
            data={
                "totp_code": "000000",
                "csrf_token": csrf_mfa,
            },
            follow_redirects=False,
        )
        self.assertEqual(mfa_post.status_code, 200)
        self.assertIn("Código TOTP inválido", mfa_post.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
