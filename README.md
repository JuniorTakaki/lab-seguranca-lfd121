# Laboratório de Segurança — LFD121

Este projeto é um laboratório prático inspirado nos conceitos do curso
**LFD121 — Developing Secure Software**, da Linux Foundation. A proposta é
demonstrar, em uma aplicação Python pequena, como identificar e aplicar
controles básicos de desenvolvimento seguro desde o código até o pipeline de
integração contínua.

O projeto não é uma aplicação web completa. Ele funciona como um exemplo
executável para estudar armazenamento seguro de senhas, proteção contra SQL
Injection, gerenciamento de configuração por variáveis de ambiente e
verificações automatizadas de segurança.

## O que a aplicação faz

O arquivo [`app.py`](./app.py):

1. Lê uma chave de API a partir da variável de ambiente `API_KEY`.
2. Obtém uma senha inicial pela variável `Senha_ADMIN_INICIAL`.
3. Cria, se necessário, o banco SQLite `usuarios.db`.
4. Cria a tabela `usuarios` com `id`, `nome` e `senha_hash`.
5. Cadastra um usuário `admin`.
6. Gera um salt aleatório e armazena a senha usando o algoritmo de hash
   `bcrypt`, em vez de guardar a senha em texto puro.
7. Consulta um usuário usando uma query parametrizada, evitando concatenar
   diretamente a entrada na instrução SQL.

Ao executar o programa, são realizados dois fluxos de demonstração: o cadastro
do administrador e uma consulta pelo nome `admin`. O banco é criado no
diretório de execução e o arquivo `usuarios.db` não faz parte do código-fonte.

## Conceitos do LFD121 aplicados

### Proteção de credenciais

As credenciais não precisam ser escritas diretamente no código: a aplicação
usa `os.getenv()` para permitir a configuração por ambiente. Em um ambiente
real, essas variáveis devem ser fornecidas por um gerenciador de segredos ou
pela infraestrutura de execução, e nunca publicadas em logs ou no repositório.

### Armazenamento seguro de senhas

A função `cadastrar_usuario()` usa `bcrypt.gensalt()` e
`bcrypt.hashpw()`. Assim, o banco guarda o hash com salt, não a senha original.
O hash é específico para senhas e deve ser usado em conjunto com uma rotina de
verificação durante a autenticação.

### Validação e parametrização de entrada

O exemplo mantém, comentada, uma versão vulnerável à SQL Injection para fins
didáticos:

```python
query = f"SELECT * FROM usuarios WHERE nome = '{nome_usuario}'"
```

A implementação utilizada substitui essa concatenação por uma query
parametrizada:

```python
query = "SELECT * FROM usuarios WHERE nome = ?"
cursor.execute(query, (nome_usuario,))
```

Essa separação entre código SQL e dados impede que o valor recebido seja
interpretado como parte da instrução SQL.

### Análise automatizada

O projeto utiliza três camadas de verificação:

- **Semgrep (SAST):** procura padrões de código potencialmente vulneráveis,
  como segredos expostos, uso inseguro de APIs e problemas de validação.
- **pip-audit (SCA):** verifica vulnerabilidades conhecidas nas dependências
  Python declaradas em `requirements.txt`.
- **Trivy:** analisa vulnerabilidades do sistema operacional e das bibliotecas
  presentes na imagem Docker.

### Segurança da imagem e do processo

O [`dockerfile`](./dockerfile) usa uma imagem Python slim, cria o usuário
não-root `appuser` e executa a aplicação com esse usuário. O `pip` também é
executado sem cache para evitar manter artefatos desnecessários na imagem.

## Pipeline de CI/CD

O workflow [`seguranca.yml`](./.github/workflows/seguranca.yml) é executado em
pushes e pull requests direcionados à branch `main`. Ele:

1. Faz checkout do código com uma action fixada em commit.
2. Configura o Python 3.11.
3. Executa o Semgrep com a configuração automática.
4. Instala e executa o `pip-audit`.
5. Constrói a imagem `lab-seguranca:latest`.
6. Executa o Trivy para vulnerabilidades `CRITICAL` e `HIGH` de sistema e
   bibliotecas.

Esse fluxo representa uma abordagem de *shift left*: os problemas de segurança
podem ser encontrados durante a alteração do código, antes da publicação ou
do deploy.

## Como executar localmente

### Pré-requisitos

- Python 3.11 ou superior
- `pip`
- Opcionalmente, Docker, Semgrep, pip-audit e Trivy

No PowerShell, a partir deste diretório:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Defina uma senha inicial antes de executar:

```powershell
$env:Senha_ADMIN_INICIAL = "troque-esta-senha"
python app.py
```

Saída esperada, com pequenas variações:

```text
Iniciando aplicação segura...
Usuário admin cadastrado.
Iniciando aplicação de teste...
Executando query segura com parâmetro
```

Cada execução cadastra outro registro `admin`, pois o exemplo não implementa
unicidade de usuário. Para recomeçar o laboratório, remova somente o banco
gerado:

```powershell
Remove-Item .\usuarios.db
```

## Como executar as análises

Com as ferramentas instaladas:

```powershell
semgrep scan --config auto --metrics=off
pip-audit -r requirements.txt
```

Para a análise de container, construa a imagem e execute o Trivy:

```powershell
docker build -t lab-seguranca:latest .
trivy image --severity HIGH,CRITICAL lab-seguranca:latest
```

O workflow do GitHub Actions é a referência oficial do projeto para a
sequência automatizada dessas etapas.

## Estrutura do projeto

```text
.
├── app.py
├── dockerfile
├── requirements.txt
└── .github/
    └── workflows/
        └── seguranca.yml
```

## Limitações e próximos passos

Este é um laboratório educacional, não uma aplicação pronta para produção.
Entre os pontos que poderiam ser evoluídos estão:

- não usar valores padrão para segredos em ambientes de produção;
- validar formato, tamanho e conteúdo dos dados de entrada;
- fechar conexões de banco com mais robustez, por exemplo usando context
  managers;
- implementar autenticação e verificação de senha;
- impedir duplicidade de usuários com uma restrição `UNIQUE`;
- adicionar testes automatizados;
- fixar e revisar todas as versões das dependências;
- configurar o Trivy para falhar o pipeline quando vulnerabilidades críticas ou
  altas forem encontradas, conforme a política do projeto;
- adicionar um `.dockerignore` para não copiar ambientes virtuais e arquivos
  locais para a imagem.

O valor principal deste repositório é mostrar o ciclo: reconhecer um padrão
inseguro, aplicar uma correção simples e verificável e automatizar a detecção
do problema no pipeline.
