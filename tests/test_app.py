import os
import tempfile
import unittest
from pathlib import Path

import app

class AppSecurityTests(unittest.TestCase):
    def setUp(self):
        self.database = tempfile.NamedTemporaryFile(delete=False)
        self.database.close()
        os.environ["DATABASE_PATH"] = self.database.name

    def tearDown(self):
        Path(self.database.name).unlink(missing_ok=True)
        os.environ.pop("DATABASE_PATH", None)

    def test_password_policy_accepts_valid_password(self):
        self.assertTrue(app.validar_senha("SenhaSegura123"))

    def test_password_policy_rejects_weak_password(self):
        for password in ("curta1A", "senhasemnumeroA", "SENHASEMNUMERO1"):
            with self.subTest(password=password):
                with self.assertRaises(ValueError):
                    app.validar_senha(password)

    def test_duplicate_user_is_rejected(self):
        app.cadastrar_usuario("admin", "SenhaSegura123")
        with self.assertRaisesRegex(ValueError, "já está cadastrado"):
            app.cadastrar_usuario("admin", "OutraSenha123")

    def test_authentication(self):
        app.cadastrar_usuario("admin", "SenhaSegura123")
        self.assertTrue(app.autenticar_usuario("admin", "SenhaSegura123"))
        self.assertFalse(app.autenticar_usuario("admin", "SenhaErrada123"))

    def test_invalid_lookup_is_rejected_before_query(self):
        app.cadastrar_usuario("admin", "SenhaSegura123")
        with self.assertRaises(ValueError):
            app.conectar_banco("' OR 1=1 --")


if __name__ == "__main__":
    unittest.main()
