import logging
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

import app


class AppSecurityTests(unittest.TestCase):
    def setUp(self):
        # Cada teste usa um banco isolado e descartável: testes não devem
        # depender de estado deixado por outros testes.
        self.database = tempfile.NamedTemporaryFile(delete=False)
        self.database.close()
        os.environ["DATABASE_PATH"] = self.database.name
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)
        Path(self.database.name).unlink(missing_ok=True)
        os.environ.pop("DATABASE_PATH", None)

    # --- Política de senha -------------------------------------------------

    def test_password_policy_accepts_valid_password(self):
        self.assertTrue(app.validar_senha("SenhaSegura123"))

    def test_password_policy_rejects_weak_password(self):
        for password in ("curta1A", "senhasemnumeroA", "SENHASEMNUMERO1", None, "A1" + "a" * 80):
            with self.subTest(password=password):
                with self.assertRaises(ValueError):
                    app.validar_senha(password)

    # --- Validação de nome (allowlist) -------------------------------------

    def test_username_allowlist_rejects_unicode_and_injection(self):
        # "аdmin" usa "а" cirílico (homóglifo); "admin\n" testa o bypass do `$`.
        for nome in ("аdmin", "ádmin", "admin\n", "' OR 1=1 --", "ab", "a" * 41, None, 123):
            with self.subTest(nome=nome):
                with self.assertRaises(ValueError):
                    app.validar_nome_usuario(nome)

    # --- Cadastro ----------------------------------------------------------

    def test_duplicate_user_is_rejected(self):
        app.cadastrar_usuario("admin", "SenhaSegura123")
        with self.assertRaisesRegex(ValueError, "já está cadastrado"):
            app.cadastrar_usuario("admin", "OutraSenha123")

    def test_password_is_stored_as_bcrypt_hash(self):
        app.cadastrar_usuario("admin", "SenhaSegura123")
        # `with sqlite3.connect(...)` NÃO fecha a conexão (só faz commit);
        # por isso usamos `closing`, igual ao app.
        with closing(sqlite3.connect(self.database.name)) as conn:
            (armazenado,) = conn.execute("SELECT senha_hash FROM usuarios").fetchone()
        self.assertNotIn(b"SenhaSegura123", armazenado)
        self.assertTrue(armazenado.startswith(b"$2b$12$"))

    # --- Autenticação ------------------------------------------------------

    def test_authentication(self):
        app.cadastrar_usuario("admin", "SenhaSegura123")
        self.assertTrue(app.autenticar_usuario("admin", "SenhaSegura123"))
        self.assertFalse(app.autenticar_usuario("admin", "SenhaErrada123"))

    def test_authentication_fails_closed_on_invalid_input(self):
        app.cadastrar_usuario("admin", "SenhaSegura123")
        for nome, senha in (("admin", None), (None, "SenhaSegura123"), ("' OR 1=1 --", "x")):
            with self.subTest(nome=nome, senha=senha):
                self.assertFalse(app.autenticar_usuario(nome, senha))

    def test_authentication_rejects_password_over_72_bytes(self):
        # O bcrypt truncaria a senha em 72 bytes; sem essa checagem, uma senha
        # com sufixo arbitrário seria aceita.
        senha = "SenhaSegura123" + "a" * 58  # exatamente 72 bytes
        app.cadastrar_usuario("admin", senha)
        self.assertTrue(app.autenticar_usuario("admin", senha))
        self.assertFalse(app.autenticar_usuario("admin", senha + "EXTRA"))

    def test_unknown_user_and_wrong_password_look_the_same(self):
        app.cadastrar_usuario("admin", "SenhaSegura123")
        logging.disable(logging.NOTSET)  # este teste precisa ver os logs
        with self.assertLogs("app", level="WARNING") as inexistente:
            self.assertFalse(app.autenticar_usuario("fantasma", "SenhaSegura123"))
        with self.assertLogs("app", level="WARNING") as senha_errada:
            self.assertFalse(app.autenticar_usuario("admin", "SenhaErrada123"))
        for registro in (inexistente.output, senha_errada.output):
            self.assertIn(app.MENSAGEM_FALHA_AUTENTICACAO, registro[0])

    # --- Consulta ----------------------------------------------------------

    def test_lookup_does_not_expose_password_hash(self):
        app.cadastrar_usuario("admin", "SenhaSegura123")
        usuario = app.buscar_usuario("admin")
        self.assertEqual(usuario[1], "admin")
        self.assertEqual(len(usuario), 2)  # apenas (id, nome)
        self.assertIsNone(app.buscar_usuario("fantasma"))

    def test_invalid_lookup_is_rejected_before_query(self):
        with self.assertRaises(ValueError):
            app.buscar_usuario("' OR 1=1 --")


class LoginRateLimitTests(unittest.TestCase):
    """Testes do limitador de tentativas, com relógio simulado."""

    SENHA = "SenhaSegura123"
    ERRADA = "SenhaErrada123"

    def setUp(self):
        self.database = tempfile.NamedTemporaryFile(delete=False)
        self.database.close()
        os.environ["DATABASE_PATH"] = self.database.name
        logging.disable(logging.CRITICAL)
        # Relógio controlado pelo teste: `self.relogio` é o "agora" do app.
        self.relogio = 1_000_000.0
        patcher = mock.patch.object(app, "_agora", side_effect=lambda: self.relogio)
        patcher.start()
        self.addCleanup(patcher.stop)
        app.cadastrar_usuario("admin", self.SENHA)

    def tearDown(self):
        logging.disable(logging.NOTSET)
        Path(self.database.name).unlink(missing_ok=True)
        os.environ.pop("DATABASE_PATH", None)

    def _errar(self, vezes, nome="admin"):
        for _ in range(vezes):
            self.assertFalse(app.autenticar_usuario(nome, self.ERRADA))

    def test_locks_after_max_failures_even_with_correct_password(self):
        self._errar(app.MAX_TENTATIVAS_LOGIN)
        self.assertTrue(app.esta_bloqueado("admin"))
        # Mesmo a senha CORRETA é recusada durante o bloqueio.
        self.assertFalse(app.autenticar_usuario("admin", self.SENHA))

    def test_lock_expires(self):
        self._errar(app.MAX_TENTATIVAS_LOGIN)
        self.relogio += app.TEMPO_BLOQUEIO_SEGUNDOS + 1
        self.assertFalse(app.esta_bloqueado("admin"))
        self.assertTrue(app.autenticar_usuario("admin", self.SENHA))

    def test_success_resets_counter(self):
        self._errar(app.MAX_TENTATIVAS_LOGIN - 1)
        self.assertTrue(app.autenticar_usuario("admin", self.SENHA))
        self._errar(app.MAX_TENTATIVAS_LOGIN - 1)
        self.assertFalse(app.esta_bloqueado("admin"))

    def test_failures_outside_window_do_not_accumulate(self):
        self._errar(app.MAX_TENTATIVAS_LOGIN - 1)
        self.relogio += app.JANELA_TENTATIVAS_SEGUNDOS + 1
        self._errar(1)
        self.assertFalse(app.esta_bloqueado("admin"))

    def test_lock_is_per_user(self):
        app.cadastrar_usuario("maria", self.SENHA)
        self._errar(app.MAX_TENTATIVAS_LOGIN, nome="admin")
        self.assertTrue(app.autenticar_usuario("maria", self.SENHA))

    def test_unknown_user_is_also_locked(self):
        # Contas inexistentes se comportam igual: o bloqueio não enumera usuários.
        self._errar(app.MAX_TENTATIVAS_LOGIN, nome="fantasma")
        self.assertTrue(app.esta_bloqueado("fantasma"))

    def test_locked_attempt_skips_bcrypt(self):
        self._errar(app.MAX_TENTATIVAS_LOGIN)
        with mock.patch.object(app.bcrypt, "checkpw") as checkpw:
            self.assertFalse(app.autenticar_usuario("admin", self.SENHA))
        checkpw.assert_not_called()

    def test_lock_survives_restart(self):
        # O estado fica no banco: um novo processo (simulado aqui por um
        # módulo recarregado) continua vendo o bloqueio.
        import importlib

        self._errar(app.MAX_TENTATIVAS_LOGIN)
        recarregado = importlib.reload(app)
        with mock.patch.object(recarregado, "_agora", side_effect=lambda: self.relogio):
            self.assertTrue(recarregado.esta_bloqueado("admin"))


if __name__ == "__main__":
    unittest.main()
