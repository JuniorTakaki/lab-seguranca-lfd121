"""Laboratório LFD121 — cadastro e autenticação de usuários com controles seguros.

Cada bloco marcado com "SEGURANÇA:" explica qual risco o código está
mitigando e por que essa abordagem é melhor do que a alternativa ingênua.
"""

import logging
import os
import re
import sqlite3
import time
from contextlib import closing, contextmanager

import bcrypt

# SEGURANÇA (logging): usamos o módulo `logging` em vez de `print`.
# - Permite controlar o nível (DEBUG/INFO/WARNING) por ambiente, sem mudar o código.
# - Em produção os logs vão para um coletor central (SIEM), essencial para
#   detectar ataques como força bruta.
# - Regra de ouro: NUNCA registrar senhas, hashes ou segredos nos logs.
logger = logging.getLogger(__name__)

# SEGURANÇA (allowlist): definimos exatamente o que É permitido, em vez de
# tentar listar o que é proibido (denylist). `str.isalnum()` aceitava qualquer
# letra Unicode ("ádmin", "аdmin" com "а" cirílico, dígitos de largura total),
# o que abre espaço para ataques de homóglifos — dois nomes visualmente iguais
# e tecnicamente diferentes. A regex ASCII fecha essa porta.
PADRAO_NOME_USUARIO = re.compile(r"[A-Za-z0-9]{3,40}")

TAMANHO_MINIMO_SENHA = 9
# O bcrypt só considera os primeiros 72 bytes; acima disso ele trunca em
# silêncio (duas senhas diferentes poderiam gerar o mesmo hash).
TAMANHO_MAXIMO_SENHA_BYTES = 72

# SEGURANÇA (custo do hash): explicitamos o fator de trabalho. Cada +1 dobra o
# tempo de cálculo — lento o suficiente para dificultar ataques offline de
# força bruta, rápido o suficiente para o login do usuário. 12 é o padrão atual
# recomendado; deixar explícito evita depender de um default que pode mudar.
BCRYPT_ROUNDS = 12

# SEGURANÇA (mensagem genérica): a mesma resposta para "usuário não existe" e
# "senha errada". Mensagens distintas permitem ENUMERAÇÃO DE USUÁRIOS: o
# atacante descobre quais contas existem e concentra o ataque nelas.
MENSAGEM_FALHA_AUTENTICACAO = "Falha de autenticação: usuário ou senha inválidos."

# SEGURANÇA (ataque de tempo / timing attack): se o usuário não existe e
# retornarmos imediatamente, a resposta leva ~1 ms; se existe, o bcrypt leva
# ~250 ms. Medindo o tempo, o atacante enumera usuários mesmo com a mensagem
# genérica. Por isso comparamos contra um hash fictício quando o usuário não
# existe, tornando os dois caminhos igualmente lentos.
_HASH_FICTICIO = bcrypt.hashpw(b"hash-ficticio-para-tempo-constante", bcrypt.gensalt(BCRYPT_ROUNDS))

# SEGURANÇA (limitador de tentativas / proteção contra força bruta):
# sem limite, um atacante testa milhares de senhas por conta. Com 5 tentativas
# a cada 15 minutos, o mesmo ataque leva anos. O bloqueio é TEMPORÁRIO de
# propósito: um bloqueio permanente permitiria que qualquer pessoa trancasse a
# conta de outra só errando a senha de propósito (negação de serviço).
MAX_TENTATIVAS_LOGIN = 5
JANELA_TENTATIVAS_SEGUNDOS = 15 * 60
TEMPO_BLOQUEIO_SEGUNDOS = 15 * 60


def _agora():
    # Isolar o relógio em uma função permite que os testes "avancem o tempo"
    # sem precisar esperar 15 minutos de verdade.
    return time.time()


# ---------------------------------------------------------------------------
# Validação de entrada
# ---------------------------------------------------------------------------

def validar_nome_usuario(nome):
    """Valida o nome de usuário. Lança ValueError se for inválido."""
    # SEGURANÇA (verificar tipo primeiro): checar o tipo antes de qualquer
    # operação evita exceções inesperadas (ex.: AttributeError em None) que
    # podem vazar detalhes internos ou derrubar a aplicação.
    if not isinstance(nome, str) or not nome:
        raise ValueError("O campo nome deve ser preenchido")
    # `fullmatch` exige que a string INTEIRA case com o padrão. Com
    # `re.match(r"^...$")`, o `$` aceitaria um "\n" no final — um clássico
    # bypass de validação que permite, por exemplo, injeção em logs.
    if not PADRAO_NOME_USUARIO.fullmatch(nome):
        raise ValueError(
            "Nome de usuário inválido! Use de 3 a 40 caracteres, apenas letras (A-Z) e números."
        )
    return True


def validar_senha(senha):
    """Aplica a política de senha. Lança ValueError se não atender."""
    if not isinstance(senha, str):
        raise ValueError("A senha deve ser um texto")
    if len(senha) < TAMANHO_MINIMO_SENHA:
        raise ValueError(f"A senha deve ter pelo menos {TAMANHO_MINIMO_SENHA} caracteres")
    if len(senha.encode("utf-8")) > TAMANHO_MAXIMO_SENHA_BYTES:
        raise ValueError(f"A senha não pode exceder {TAMANHO_MAXIMO_SENHA_BYTES} bytes")
    if not any(c.isupper() for c in senha):
        raise ValueError("A senha deve conter letra maiúscula")
    if not any(c.islower() for c in senha):
        raise ValueError("A senha deve conter letra minúscula")
    if not any(c.isdigit() for c in senha):
        raise ValueError("A senha deve conter número")
    return True


# ---------------------------------------------------------------------------
# Acesso ao banco de dados
# ---------------------------------------------------------------------------

def _caminho_banco():
    # SEGURANÇA (configuração externa): o caminho vem do ambiente, não fica
    # fixo no código — o mesmo artefato roda em teste, CI e produção.
    return os.getenv("DATABASE_PATH", "usuarios.db")


def _conectar():
    # SEGURANÇA (DRY = menos falhas): antes a conexão era aberta de três
    # formas repetidas. Um único ponto de entrada garante que toda conexão
    # receba as mesmas configurações seguras e facilita auditoria.
    conn = sqlite3.connect(_caminho_banco())
    # Garante que restrições (UNIQUE, NOT NULL, FOREIGN KEY) sejam aplicadas.
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def inicializar_banco():
    """Cria o schema se ele ainda não existir."""
    # SEGURANÇA (separação de responsabilidades): criar tabela é tarefa de
    # inicialização, não do cadastro. Misturar as duas coisas exige que a
    # função de negócio tenha privilégio de DDL (CREATE/ALTER) — contrariando
    # o princípio do menor privilégio.
    with closing(_conectar()) as conn, conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT UNIQUE NOT NULL,
                senha_hash BLOB NOT NULL
            )
            """
        )
        # SEGURANÇA (estado persistente): as falhas ficam no banco, não em uma
        # variável na memória. Um contador em memória zera a cada reinício do
        # processo, e o atacante só precisaria derrubar ou reiniciar o serviço
        # para ganhar novas tentativas.
        # Não há FOREIGN KEY para `usuarios` de propósito: nomes que NÃO
        # existem também são contados (veja `_registrar_falha`).
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tentativas_login (
                nome TEXT PRIMARY KEY,
                falhas INTEGER NOT NULL,
                inicio_janela REAL NOT NULL,
                bloqueado_ate REAL NOT NULL DEFAULT 0
            )
            """
        )


@contextmanager
def _transacao_imediata():
    # SEGURANÇA (condição de corrida / race condition): "ler contador → somar
    # 1 → gravar" em passos separados permite que duas requisições simultâneas
    # leiam o mesmo valor e uma das falhas se perca. Com tentativas em
    # paralelo, o atacante passaria do limite. `BEGIN IMMEDIATE` reserva o
    # direito de escrita ANTES da leitura, então o ciclo inteiro é atômico.
    conn = _conectar()
    conn.isolation_level = None  # controlamos a transação manualmente
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Limitador de tentativas de login
# ---------------------------------------------------------------------------

def esta_bloqueado(nome):
    """Indica se o nome está temporariamente bloqueado por excesso de falhas."""
    with closing(_conectar()) as conn:
        linha = conn.execute(
            "SELECT bloqueado_ate FROM tentativas_login WHERE nome = ?", (nome,)
        ).fetchone()
    return linha is not None and linha[0] > _agora()


def _registrar_falha(nome):
    agora = _agora()
    with _transacao_imediata() as conn:
        linha = conn.execute(
            "SELECT falhas, inicio_janela FROM tentativas_login WHERE nome = ?", (nome,)
        ).fetchone()

        # Janela deslizante: falhas antigas (fora da janela) não contam mais.
        # Assim, quem erra a senha uma vez por semana nunca é bloqueado.
        if linha is None or agora - linha[1] > JANELA_TENTATIVAS_SEGUNDOS:
            falhas, inicio_janela = 1, agora
        else:
            falhas, inicio_janela = linha[0] + 1, linha[1]

        bloqueado_ate = 0
        if falhas >= MAX_TENTATIVAS_LOGIN:
            bloqueado_ate = agora + TEMPO_BLOQUEIO_SEGUNDOS
            # O contador volta a zero: quando o bloqueio expira, o usuário
            # legítimo recebe um novo lote de tentativas.
            falhas, inicio_janela = 0, agora
            # SEGURANÇA (monitoramento): bloqueios são eventos que a equipe de
            # segurança deve ver. Vários bloqueios em sequência indicam ataque.
            logger.warning("Bloqueio temporário aplicado ao usuário: %s", nome)

        # UPSERT: insere a primeira falha ou atualiza o registro existente
        # em um único comando.
        conn.execute(
            """
            INSERT INTO tentativas_login (nome, falhas, inicio_janela, bloqueado_ate)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(nome) DO UPDATE SET
                falhas = excluded.falhas,
                inicio_janela = excluded.inicio_janela,
                bloqueado_ate = excluded.bloqueado_ate
            """,
            (nome, falhas, inicio_janela, bloqueado_ate),
        )


def _limpar_falhas(nome):
    # Login bem-sucedido zera o histórico: errar 4 vezes, acertar e depois
    # errar mais 4 não deve bloquear o usuário legítimo.
    with closing(_conectar()) as conn, conn:
        conn.execute("DELETE FROM tentativas_login WHERE nome = ?", (nome,))


# ---------------------------------------------------------------------------
# Regras de negócio
# ---------------------------------------------------------------------------

def cadastrar_usuario(nome, senha_pura):
    """Cadastra um usuário armazenando apenas o hash bcrypt da senha."""
    # SEGURANÇA (validar antes de processar): nenhuma entrada chega ao banco
    # ou ao bcrypt sem passar pela validação.
    validar_nome_usuario(nome)
    validar_senha(senha_pura)

    # O bcrypt gera um salt aleatório por senha e o embute no próprio hash.
    # Assim, dois usuários com a mesma senha têm hashes diferentes, e tabelas
    # pré-computadas (rainbow tables) se tornam inúteis.
    senha_hash = bcrypt.hashpw(senha_pura.encode("utf-8"), bcrypt.gensalt(BCRYPT_ROUNDS))

    inicializar_banco()
    with closing(_conectar()) as conn, conn:
        try:
            # SEGURANÇA (SQL Injection): placeholders `?` fazem o driver tratar
            # os valores como DADOS, nunca como parte do comando SQL.
            conn.execute(
                "INSERT INTO usuarios (nome, senha_hash) VALUES (?, ?)",
                (nome, senha_hash),
            )
        except sqlite3.IntegrityError as exc:
            # `from exc` preserva a causa para depuração, mas a mensagem ao
            # usuário não expõe detalhes do banco (nome da tabela, constraint).
            raise ValueError(f"O usuário '{nome}' já está cadastrado") from exc

    logger.info("Usuário cadastrado: %s", nome)


def autenticar_usuario(nome, senha_fornecida):
    """Retorna True se as credenciais forem válidas, False caso contrário."""
    # SEGURANÇA (fail closed / falhar fechado): qualquer entrada inválida
    # resulta em "acesso negado", nunca em exceção não tratada. Um erro
    # inesperado em código de autenticação não pode virar acesso concedido
    # nem derrubar o serviço.
    try:
        validar_nome_usuario(nome)
    except ValueError:
        logger.warning(MENSAGEM_FALHA_AUTENTICACAO)
        return False

    if not isinstance(senha_fornecida, str):
        logger.warning(MENSAGEM_FALHA_AUTENTICACAO)
        return False

    senha_bytes = senha_fornecida.encode("utf-8")
    # Senhas acima de 72 bytes nunca foram aceitas no cadastro; rejeitar aqui
    # evita que o truncamento silencioso do bcrypt aceite uma senha "parecida".
    if len(senha_bytes) > TAMANHO_MAXIMO_SENHA_BYTES:
        logger.warning(MENSAGEM_FALHA_AUTENTICACAO)
        return False

    inicializar_banco()

    # SEGURANÇA (bloqueio antes do bcrypt): durante o bloqueio, a senha NÃO é
    # verificada, nem mesmo a correta. Se fosse, o atacante continuaria
    # testando senhas e só "esperaria" o bloqueio para usar a que funcionou.
    # Pular o bcrypt também economiza CPU: um ataque em massa não consegue
    # sobrecarregar o servidor forçando milhares de hashes caros.
    # A resposta pública continua genérica; o motivo vai apenas para o log.
    if esta_bloqueado(nome):
        logger.warning("Tentativa durante bloqueio temporário para o usuário: %s", nome)
        return False

    with closing(_conectar()) as conn:
        resultado = conn.execute(
            "SELECT senha_hash FROM usuarios WHERE nome = ?", (nome,)
        ).fetchone()

    # Tempo constante: mesmo sem usuário, executamos o checkpw (ver
    # _HASH_FICTICIO). O resultado é descartado, mas o tempo gasto é o mesmo.
    hash_armazenado = resultado[0] if resultado else _HASH_FICTICIO
    senha_confere = bcrypt.checkpw(senha_bytes, hash_armazenado)

    # `checkpw` já compara em tempo constante internamente. Nunca compare
    # hashes com `==`, pois a comparação para no primeiro byte diferente.
    if resultado and senha_confere:
        _limpar_falhas(nome)
        logger.info("Autenticação bem-sucedida para o usuário: %s", nome)
        return True

    # SEGURANÇA (contar também usuários inexistentes): se só contas reais
    # fossem bloqueadas, o atacante erraria 5 vezes e veria quem "ficou
    # bloqueado", e o bloqueio viraria uma nova forma de enumerar usuários.
    # Como o nome já passou pela allowlist (máx. 40 caracteres ASCII), gravar
    # o nome no banco é seguro.
    _registrar_falha(nome)

    # O log interno pode ter mais detalhe para a equipe de segurança, mas a
    # resposta pública permanece genérica.
    logger.warning("%s (usuário informado: %s)", MENSAGEM_FALHA_AUTENTICACAO, nome)
    return False


def buscar_usuario(nome_usuario):
    """Retorna (id, nome) do usuário, ou None se ele não existir."""
    # SEGURANÇA (minimização de dados): a versão anterior (`conectar_banco`)
    # fazia `SELECT *` e devolvia o hash da senha para quem chamasse a função.
    # Selecionar apenas as colunas necessárias impede vazamento acidental do
    # hash (em uma resposta de API, em um log, em um template...). O nome
    # anterior também era enganoso: a função não "conecta", ela "busca".
    validar_nome_usuario(nome_usuario)
    inicializar_banco()
    with closing(_conectar()) as conn:
        return conn.execute(
            "SELECT id, nome FROM usuarios WHERE nome = ?", (nome_usuario,)
        ).fetchone()


# ---------------------------------------------------------------------------
# Ponto de entrada
# ---------------------------------------------------------------------------

def _obter_variavel_obrigatoria(nome_variavel):
    # SEGURANÇA (fail fast + segredos fora do código): a aplicação se recusa a
    # iniciar sem os segredos, em vez de usar um valor padrão "provisório" que
    # acaba indo para produção. A mensagem cita o NOME da variável, nunca o valor.
    valor = os.getenv(nome_variavel)
    if not valor:
        raise EnvironmentError(
            f"ERRO CRÍTICO: a variável de ambiente {nome_variavel} não está definida!"
        )
    return valor


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logger.info("Iniciando aplicação segura...")

    _obter_variavel_obrigatoria("API_KEY")
    # Nome padronizado em MAIÚSCULAS: no Linux (Docker/CI) variáveis de
    # ambiente diferenciam maiúsculas e minúsculas; o nome antigo
    # "Senha_ADMIN_INICIAL" divergia da própria mensagem de erro.
    senha_inicial = _obter_variavel_obrigatoria("SENHA_ADMIN_INICIAL")

    inicializar_banco()
    if buscar_usuario("admin") is None:
        cadastrar_usuario("admin", senha_inicial)
    else:
        # Idempotência: reiniciar o container não deve quebrar a aplicação
        # nem sobrescrever a senha de um admin já existente.
        logger.info("Usuário admin já existe; cadastro inicial ignorado.")

    autenticar_usuario("admin", senha_inicial)


if __name__ == "__main__":
    main()
