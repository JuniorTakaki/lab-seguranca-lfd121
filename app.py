import os
import sqlite3
from contextlib import closing
import bcrypt

def validar_nome_usuario(nome):
    if not nome or not isinstance(nome, str):
        raise ValueError("O campo nome deve ser preenchido")
    if not nome.isalnum() or not (3 <= len(nome) <= 40):
        raise ValueError("Nome de usuário inválido! Deve conter apenas caracteres alfanuméricos.")
    return True

def validar_senha(senha):
    if not isinstance(senha, str):
        raise ValueError("A senha deve ser um texto")
    if len(senha) < 9:
        raise ValueError("A senha deve ter pelo menos 9 caracteres")
    if len(senha.encode("utf-8")) > 72:
        raise ValueError("A senha não pode exceder 72 bytes")
    if not any(caractere.isupper() for caractere in senha):
        raise ValueError("A senha deve conter letra maiúscula")
    if not any(caractere.islower() for caractere in senha):
        raise ValueError("A senha deve conter letra minúscula")
    if not any(caractere.isdigit() for caractere in senha):
        raise ValueError("A senha deve conter número")
    return True

def cadastrar_usuario( nome, senha_pura):
    validar_nome_usuario(nome) # valido o nome com base na função acima 
    validar_senha(senha_pura)
    # 1. Gera um "salt" aleatório e faz o hash seguro da senha
    salt = bcrypt.gensalt()
    senha_hash = bcrypt.hashpw(senha_pura.encode('utf-8'), salt)


    with closing(sqlite3.connect(os.getenv("DATABASE_PATH", "usuarios.db"))) as conn:
        with conn:
            conn.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT UNIQUE NOT NULL,
                senha_hash BLOB NOT NULL
                )
            ''')
            try:
                conn.execute(
                    "INSERT INTO usuarios (nome, senha_hash) VALUES (?, ?)",
                    (nome, senha_hash),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError(f"O usuário '{nome}' já está cadastrado") from exc
    print(f"Usuário {nome} cadastrado.")

def autenticar_usuario(nome, senha_fornecida):
    validar_nome_usuario(nome) #valido também nessa função a autenticação.

    with closing(sqlite3.connect(os.getenv("DATABASE_PATH", "usuarios.db"))) as conn:
        resultado = conn.execute(
            "SELECT senha_hash FROM usuarios WHERE nome = ?", (nome,)
        ).fetchone()

    if not resultado:
        print(f"Falha de autenticação: Usuário '{nome}' não encontrado.")
        return False

    senha_hash_armazenado = resultado[0]

    # Valida a senha fornecida contra o hash usando bcrypt.checkpw
    if  bcrypt.checkpw(senha_fornecida.encode('utf-8'), senha_hash_armazenado):
        print(f"Sucesso: Autenticação bem-sucedida para o usuário '{nome}'!")
        return True
    else:
        print(f"Falha de autenticação: Senha incorreta para o usuário '{nome}'.")
        return False
    
def conectar_banco(nome_usuario):
    validar_nome_usuario(nome_usuario)
    with closing(sqlite3.connect(os.getenv("DATABASE_PATH", "usuarios.db"))) as conn:
        return conn.execute(
            "SELECT * FROM usuarios WHERE nome = ?", (nome_usuario,)
        ).fetchall()

if __name__ == "__main__":
    print("Iniciando aplicação segura...")

    API_KEY =  os.getenv("API_KEY")
    if not API_KEY:
        raise EnvironmentError("ERRO Crítico: A variável de ambiente API_KEY não está definida!")

    senha_inicial = os.getenv("Senha_ADMIN_INICIAL")
    if not senha_inicial:
        raise EnvironmentError("ERRO CRÍTICO: A variável de ambiente SENHA_ADMIN_INICIAL não está definida!")

    cadastrar_usuario("admin", senha_inicial)
    autenticar_usuario("admin", senha_inicial)
