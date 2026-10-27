import os
import sqlite3

# 1. Credencial hardcoded (Erro clássico que ferramentas de segredo pegam)
# API_KEY = "sk-live-123456789abcdefsecretkey"
# ADMIN_PASSWORD = "senha_super_secreta_123"

API_KEY =  os.getenv( "API_KEY", "chave-segura")

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