import os
import sqlite3
import bcrypt

# 1. Credencial hardcoded (Erro clássico que ferramentas de segredo pegam)
# API_KEY = "sk-live-123456789abcdefsecretkey"
# ADMIN_PASSWORD = "senha_super_secreta_123"

API_KEY =  os.getenv( "API_KEY", "chave-segura")

def cadastrar_usuario( nome, senh_pura):
    # 1. Gera um "salt" aleatório e faz o hash seguro da senha
    salt = bcrypt.gensalt()
    senha_hash = bcrypt.hashpw(senh_pura.encode('utf-8'), salt)

    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT,
        senha_hash BLOB
        )
    ''')

    cursor.execute("INSERT INTO usuarios (nome, senha_hash) VALUES (?, ?)", (nome , senha_hash))
    conn.commit()
    conn.close()
    print(f"Usuário {nome} cadastrado.")

if __name__ == "__main__":
    print("Iniciando aplicação segura...")
    senha_inicial = os.getenv("Senha_ADMIN_INICIAL", "senha_padrao_temporaria")
    cadastrar_usuario("admin", senha_inicial)


def conectar_banco(nome_usuario):
    conexao = sqlite3.connect('usuarios.db')
    cursor = conexao.cursor()
    
    # 2. Vulnerabilidade de SQL Injection (Foco de Input Validation do LFD121)
    # query = f"SELECT * FROM usuarios WHERE nome = '{nome_usuario}'"
    query = "SELECT * FROM usuarios WHERE nome = ?"
    print(f"Executando query segura com parâmetro")
    # print(f"Executando query: {query}")
    
    # cursor.execute(query)
    # return cursor.fetchall()
    cursor.execute(query, (nome_usuario,))
    return cursor.fetchall()


if __name__ == "__main__":
    print("Iniciando aplicação de teste...")
    conectar_banco("admin")