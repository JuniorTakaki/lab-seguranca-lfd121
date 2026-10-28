import os
import sqlite3
import bcrypt

# 1. Credencial hardcoded (Erro clássico que ferramentas de segredo pegam)

# semgrep scan --config auto
#pip-audit -r requirements.txt
#semgrep scan --config auto --metrics=off

def validar_nome_usuario(nome):
    if not nome or not isinstance(nome, str):
        raise ValueError("O campo nome deve ser preenchido")
    if not nome.isalnum() or not (3 <= len(nome) <= 40):
        raise ValueError("Nome de usuário inválido! Deve conter apenas caracteres alfanuméricos.")
    return True

def cadastrar_usuario( nome, senha_pura):
    validar_nome_usuario(nome) # valido o nome com base na função acima 

    # 1. Gera um "salt" aleatório e faz o hash seguro da senha
    salt = bcrypt.gensalt()
    senha_hash = bcrypt.hashpw(senha_pura.encode('utf-8'), salt)

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

def autenticar_usuario(nome, senha_fornecida):
    validar_nome_usuario(nome) #valido também nessa função a autenticação.

    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()

    # Buscar o hash da senha armazenado do user especifico.
    cursor.execute("SELECT senha_hash FROM usuários WHERE nome = ?", (nome,))
    resultado = cursor.fetchone()
    conn.close()

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
    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()
    query = "SELECT * FROM usuarios WHERE nome = ?"
    cursor.execute(query, (nome_usuario,))
    resultado =  cursor.fetchall()
    conn.close()
    return resultado

    # 2. Vulnerabilidade de SQL Injection (Foco de Input Validation do LFD121)
    # query = f"SELECT * FROM usuarios WHERE nome = '{nome_usuario}'"
    # print(f"Executando query: {query}")
    # cursor.execute(query)
    # return cursor.fetchall()
    
if __name__ == "__main__":
    print("Iniciando aplicação segura...")

    API_KEY =  os.getenv( "API_KEY", "chave-segura")
    if not API_KEY:
        raise EnvironmentError("ERRO Crítico: A variável de ambiente API_KEY não está definida!")

    senha_inicial = os.getenv("Senha_ADMIN_INICIAL")
    if not senha_inicial:
        raise EnvironmentError("ERRO CRÍTICO: A variável de ambiente SENHA_ADMIN_INICIAL não está definida!")

    cadastrar_usuario("admin", senha_inicial)
    autenticar_usuario("admin", senha_inicial)

