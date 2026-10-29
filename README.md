# Laboratório de Segurança — LFD121

Laboratório prático inspirado no curso **LFD121 — Developing Secure
Software**, da Linux Foundation. O projeto demonstra controles básicos de
desenvolvimento seguro em uma aplicação Python com SQLite, bcrypt, Docker e
GitHub Actions.

> Este é um projeto educacional. Não use credenciais ou dados reais e não
> exponha a aplicação publicamente sem controles adicionais.

## Objetivos de aprendizagem

- Validar entradas antes de processá-las.
- Armazenar senhas usando hash com salt, nunca em texto puro.
- Evitar SQL Injection com consultas parametrizadas.
- Impedir usuários duplicados com uma restrição `UNIQUE`.
- Fechar conexões de banco de dados corretamente.
- Criar testes automatizados para comportamentos esperados e inválidos.
- Reduzir riscos da imagem Docker.
- Automatizar SAST, SCA e análise de vulnerabilidades no CI.

## Estrutura

```text
.
├── app.py
├── tests/
│   └── test_app.py
├── dockerfile
├── .dockerignore
├── requirements.txt
├── README.md
└── .github/
    └── workflows/
        └── seguranca.yml
```

O diretório `.venv/`, o banco `usuarios.db`, caches e arquivos `.env` são
locais e não devem ser versionados nem enviados para o contexto de build.
Essas exclusões estão definidas em [`.dockerignore`](./.dockerignore).

## Controles implementados

### Validação de entrada e senha

[`app.py`](./app.py) valida o nome de usuário e a senha antes do cadastro.
A política atual exige:

- senha em formato texto;
- pelo menos 9 caracteres;
- no máximo 72 bytes, limite de entrada do bcrypt;
- pelo menos uma letra maiúscula;
- pelo menos uma letra minúscula;
- pelo menos um número.

### Proteção de credenciais

As senhas são processadas com `bcrypt.gensalt()` e `bcrypt.hashpw()`. O hash,
e não a senha original, é armazenado no SQLite. As configurações
`API_KEY` e `Senha_ADMIN_INICIAL` são lidas por variáveis de ambiente e não
possuem valor padrão no código.

### Banco de dados

O banco usa a tabela `usuarios`, com:

- `nome TEXT UNIQUE NOT NULL`, para impedir duplicidade;
- `senha_hash BLOB NOT NULL`;
- consultas parametrizadas com `?`;
- conexões fechadas com `contextlib.closing`;
- transações controladas com context managers.

O caminho do banco pode ser alterado pela variável `DATABASE_PATH`. O padrão
é `usuarios.db`.

### Testes

Os testes em [`tests/test_app.py`](./tests/test_app.py) cobrem:

- aceitação e rejeição da política de senha;
- bloqueio de usuário duplicado;
- autenticação com senha correta;
- rejeição de senha incorreta;
- rejeição de entrada inválida no acesso ao banco.

## Execução local

### Pré-requisitos

- Python 3.12;
- `pip`;
- PowerShell no Windows.

Opcionalmente: Docker, Semgrep, pip-audit e Trivy.

Crie o ambiente virtual e instale as dependências:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Configure os valores necessários:

```powershell
$env:API_KEY = "chave-apenas-para-o-laboratorio"
$env:Senha_ADMIN_INICIAL = "SenhaSegura123"
python app.py
```

Para executar os testes:

```powershell
python -m py_compile app.py
python -m unittest discover -s tests -v
```

Resultado esperado:

```text
Ran 5 tests
OK
```

Para recriar o banco do laboratório, remova somente o arquivo gerado:

```powershell
Remove-Item .\usuarios.db
```

## Docker

A imagem usa `python:3.12-slim`, instala somente a dependência declarada,
desativa bytecode e buffering desnecessários, e executa como o usuário
não-root `appuser`.

Construção:

```powershell
docker build -t lab-seguranca:latest .
```

Execução:

```powershell
docker run --rm `
  -e API_KEY=chave-apenas-para-o-laboratorio `
  -e Senha_ADMIN_INICIAL=SenhaSegura123 `
  lab-seguranca:latest
```

## Pipeline de segurança

O workflow [`seguranca.yml`](./.github/workflows/seguranca.yml) é executado em
pushes e pull requests para `main`. Ele:

1. fixa as GitHub Actions por commit;
2. configura o Python 3.12;
3. executa Semgrep como SAST;
4. executa pip-audit como SCA;
5. executa os testes automatizados;
6. constrói a imagem Docker;
7. executa Trivy para vulnerabilidades `HIGH` e `CRITICAL`.

O Trivy usa `exit-code: "1"`, portanto o job falha quando encontra
vulnerabilidades dentro da política definida. Exceções devem ser justificadas,
documentadas e aprovadas.

As verificações locais equivalentes são:

```powershell
semgrep scan --config auto --metrics=off
pip-audit -r requirements.txt
docker build -t lab-seguranca:latest .
trivy image --severity HIGH,CRITICAL lab-seguranca:latest
```

## Dependências

O projeto declara somente:

```text
bcrypt==4.2.1
```

Manter dependências não utilizadas fora do projeto reduz a superfície de
ataque e facilita a revisão de vulnerabilidades da cadeia de fornecimento.

## Limitações e próximos passos

Este laboratório ainda não implementa:

- autorização e papéis;
- sessões seguras;
- limite de tentativas e proteção contra brute force;
- rotação e gerenciamento centralizado de segredos;
- mensagens genéricas para evitar enumeração de usuários;
- SBOM, assinatura e verificação da imagem;
- política formal de retenção e monitoramento.

Esses itens são evoluções naturais depois dos fundamentos. O objetivo do
projeto é registrar o ciclo de identificar um risco, aplicar um controle,
testar o comportamento e automatizar a verificação no pipeline.
