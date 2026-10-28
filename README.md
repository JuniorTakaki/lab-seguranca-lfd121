# Laboratório de Segurança — LFD121

Este repositório contém um laboratório prático inspirado nos conceitos do
curso **LFD121 — Developing Secure Software**, da Linux Foundation. O
objetivo é demonstrar controles básicos de desenvolvimento seguro em uma
aplicação Python que utiliza SQLite, hash de senhas e consultas parametrizadas,
além de verificações automatizadas no pipeline de CI.

> **Estado atual:** os conflitos de merge do `app.py` foram removidos e o
> projeto está em processo de aprimoramento. Ainda existem vulnerabilidades e
> inconsistências funcionais documentadas neste arquivo; portanto, a aplicação
> continua destinada exclusivamente ao laboratório.

## Estrutura do projeto

```text
.
├── app.py
├── dockerfile
├── requirements.txt
├── README.md
└── .github/
    └── workflows/
        └── seguranca.yml
```

O diretório `.venv/`, quando criado localmente, é um ambiente virtual de
desenvolvimento e não faz parte da aplicação nem deve ser versionado.

## Componentes atuais

### `app.py`

O arquivo contém exemplos de:

- leitura de configurações por variáveis de ambiente;
- criação de um banco SQLite chamado `usuarios.db`;
- criação da tabela `usuarios`;
- armazenamento de senhas com `bcrypt`;
- validação básica do nome de usuário;
- uso de consultas SQL parametrizadas para evitar SQL Injection;
- autenticação com `bcrypt.checkpw`.

Os conflitos de merge foram removidos e o arquivo agora possui uma única
implementação de cada função e um único bloco de entrada. Ainda há problemas
que precisam ser corrigidos, como a consulta de autenticação que referencia
`usuários` enquanto a tabela criada se chama `usuarios`, além do uso de um
valor padrão para `API_KEY`.

### `requirements.txt`

As dependências declaradas atualmente são:

- `bcrypt==4.2.1`;
- `flask>=2.3.2`;
- `idna>=3.15`;
- `requests>=2.33.0`;
- `urllib3>=2.8.0`.

O código presente em `app.py` utiliza diretamente `bcrypt`. As demais
dependências permanecem declaradas para as verificações de dependências e para
eventuais extensões do laboratório.

### `dockerfile`

O container:

1. utiliza a imagem `python:3.12-slim`;
2. define `/app` como diretório de trabalho;
3. cria o usuário não-root `appuser`;
4. instala as dependências sem manter o cache do `pip`;
5. copia os arquivos para a imagem com `appuser` como proprietário;
6. executa `python app.py`.

## Práticas do LFD121 aplicadas no laboratório

O laboratório coloca em prática uma abordagem de desenvolvimento seguro
orientada à prevenção: identificar o risco no código, aplicar um controle
específico e verificar automaticamente se o problema continua presente.

| Prática estudada | Aplicação neste projeto | Evidência |
|---|---|---|
| Não armazenar segredos no código | `API_KEY` e `Senha_ADMIN_INICIAL` são obtidas por variáveis de ambiente | `os.getenv()` em `app.py` |
| Proteger credenciais | A senha não é salva em texto puro; é gerado um salt e armazenado um hash | `bcrypt.gensalt()` e `bcrypt.hashpw()` |
| Validar entradas | O nome de usuário é validado quanto ao tipo, tamanho e caracteres permitidos | `validar_nome_usuario()` |
| Evitar injeção de SQL | O nome do usuário é enviado como parâmetro, separado da instrução SQL | `cursor.execute(query, (nome_usuario,))` |
| Automatizar a análise de segurança | O código e as dependências são analisados no CI | Semgrep e pip-audit |
| Reduzir riscos da imagem | A imagem usa uma variante slim e executa como usuário não-root | `dockerfile` |
| Verificar dependências e imagem | Dependências Python e bibliotecas do container são examinadas | pip-audit e Trivy |
| Aplicar shift left | As verificações acontecem em pushes e pull requests antes do deploy | `.github/workflows/seguranca.yml` |

Essas práticas representam os controles exercitados neste repositório. O
laboratório não substitui requisitos de uma aplicação de produção, como
autorização, rotação de segredos, gestão de sessões, monitoramento e testes de
segurança mais abrangentes.

## Vulnerabilidades conhecidas e evolução do projeto

O projeto ainda possui vulnerabilidades e pontos de melhoria. Eles fazem parte
do estado atual do laboratório e servem para demonstrar o processo de
identificação, correção e verificação de falhas de segurança. O objetivo não é
apresentar uma aplicação pronta para produção, mas registrar a evolução do
código com base nas práticas estudadas no LFD121.

Entre os pontos atualmente conhecidos estão:

- inconsistência no nome da tabela usada pela autenticação (`usuários` versus
  `usuarios`);
- valor padrão de `API_KEY`, que não deve ser utilizado para segredos reais;
- ausência de uma restrição de unicidade para impedir usuários duplicados;
- conexões SQLite que ainda podem ser tratadas com mais robustez;
- dependências declaradas com versões mínimas, em vez de um conjunto
  completamente fixado e revisado;
- pipeline do Trivy configurado para reportar vulnerabilidades sem falhar o
  job (`exit-code: "0"`);
- ausência de testes automatizados e de um `.dockerignore`;
- controles ainda incompletos para autenticação, autorização, política de
  senhas, rotação de segredos e proteção de dados.

Esses riscos estão sendo tratados de forma incremental. O projeto já aplica ou
está incorporando práticas do curso, como:

1. identificar padrões inseguros no código;
2. substituir segredos expostos por configuração via ambiente;
3. aplicar hash de senha com salt;
4. validar entradas e parametrizar consultas SQL;
5. executar SAST, SCA e análise de vulnerabilidades da imagem;
6. revisar os resultados no pipeline antes da integração.

Enquanto essas melhorias não forem concluídas, o software deve ser executado
somente em ambiente de laboratório, sem dados reais, credenciais reais ou
exposição pública. Os achados devem ser tratados como itens de evolução, e
não como uma garantia de segurança da aplicação.

## Fluxo prático do laboratório

O exercício segue este ciclo:

1. identificar um padrão inseguro, como senha em texto puro, segredo
   hardcoded ou SQL montado por concatenação;
2. substituir o padrão por uma implementação mais segura;
3. executar ferramentas automatizadas para procurar problemas no código, nas
   dependências e na imagem;
4. revisar os resultados e corrigir os achados;
5. repetir as verificações no pipeline de integração contínua.

O exemplo de SQL Injection permanece comentado em `app.py` apenas para
comparar a implementação vulnerável com a consulta parametrizada. Ele não deve
ser reativado.

## Conceitos de segurança demonstrados

### Armazenamento de senhas

O código usa `bcrypt.gensalt()` e `bcrypt.hashpw()` para gerar um salt e
armazenar um hash da senha, em vez da senha em texto puro. Em uma aplicação
real, o hash deve ser validado durante a autenticação e os requisitos de
complexidade, tamanho e exposição de senhas devem ser definidos pela política
do sistema.

### Parametrização de consultas

O exemplo de consulta segura separa o comando SQL dos dados fornecidos pelo
usuário:

```python
query = "SELECT * FROM usuarios WHERE nome = ?"
cursor.execute(query, (nome_usuario,))
```

A versão vulnerável por concatenação de strings permanece comentada no código
para fins didáticos:

```python
query = f"SELECT * FROM usuarios WHERE nome = '{nome_usuario}'"
```

Essa versão não deve ser habilitada em uma aplicação real.

### Validação de entrada

A validação de `nome_usuario` restringe o valor a uma string alfanumérica com
comprimento entre 3 e 40 caracteres. Essa validação reduz entradas inválidas,
mas não substitui a parametrização da consulta: são controles diferentes e
ambos são necessários.

### Configuração por ambiente

O código lê `API_KEY` e `Senha_ADMIN_INICIAL` usando `os.getenv()`. Segredos
reais devem ser fornecidos por um gerenciador de segredos ou pela
infraestrutura de execução, e nunca devem ser gravados no código-fonte,
versionados ou exibidos em logs.

Embora os conflitos de merge tenham sido removidos, `API_KEY` ainda possui um
valor padrão no código. Esse comportamento é inadequado para produção e deve
ser substituído por uma configuração obrigatória, sem segredo embutido.

### Verificação automatizada

As ferramentas têm objetivos complementares:

- **Semgrep (SAST):** procura padrões perigosos no código-fonte, como uso
  inseguro de APIs e possíveis segredos expostos;
- **pip-audit (SCA):** compara as dependências Python declaradas com
  vulnerabilidades conhecidas;
- **Trivy:** verifica vulnerabilidades do sistema operacional e das bibliotecas
  presentes na imagem Docker.

Uma análise automatizada ajuda a detectar problemas cedo, mas não garante que
o software esteja seguro. Os resultados precisam ser revisados por uma pessoa
e complementados por testes e análise de requisitos.

## Pipeline de segurança

O workflow
[`seguranca.yml`](./.github/workflows/seguranca.yml) é executado em pushes e
pull requests direcionados à branch `main`. Atualmente, ele:

1. faz checkout do código usando uma action fixada em commit;
2. configura o Python 3.12;
3. executa o Semgrep com a configuração automática;
4. instala e executa o `pip-audit` sobre `requirements.txt`;
5. constrói a imagem `lab-seguranca:latest`;
6. executa o Trivy para vulnerabilidades `HIGH` e `CRITICAL` do sistema e das
   bibliotecas.

O passo do Trivy está configurado com `exit-code: "0"`. Assim, o resultado da
análise é exibido, mas a presença de vulnerabilidades não faz o job falhar.
Essa configuração pode ser alterada quando a política do projeto exigir que
vulnerabilidades bloqueiem o pipeline.

## Como preparar o ambiente local

### Pré-requisitos

- Python 3.12, para corresponder ao container;
- `pip`;
- PowerShell no Windows;
- opcionalmente, Docker, Semgrep, pip-audit e Trivy.

A partir da raiz do repositório:
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


Antes de executar o programa, defina as variáveis esperadas:

```powershell
$env:API_KEY = "chave-apenas-para-o-laboratorio"
=======
Defina uma senha inicial antes de executar:

```powershell

$env:Senha_ADMIN_INICIAL = "troque-esta-senha"
python app.py
```


O programa poderá criar o arquivo local `usuarios.db`. Esse arquivo é gerado
em tempo de execução e não deve ser versionado. A autenticação ainda não
funcionará corretamente até que o nome da tabela na consulta seja corrigido.

Para recriar o banco do laboratório, remova somente o arquivo gerado:

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


Para analisar a imagem Docker:

Para a análise de container, construa a imagem e execute o Trivy:


```powershell
docker build -t lab-seguranca:latest .
trivy image --severity HIGH,CRITICAL lab-seguranca:latest
```


O workflow do GitHub Actions é a referência para a sequência automatizada
dessas verificações.

## Limitações e próximos passos

Antes de considerar o laboratório funcional, é necessário:

- corrigir o nome da tabela na consulta de autenticação;
- manter a validação das variáveis obrigatórias sem valores padrão para
  segredos;
- garantir que as variáveis obrigatórias não tenham segredos padrão;
- fechar conexões SQLite com mais robustez, preferencialmente com context
  managers;
- impedir duplicidade de usuários com uma restrição `UNIQUE`;
- adicionar testes automatizados;
- fixar e revisar as versões das dependências;
- decidir se o Trivy deve fazer o pipeline falhar ao encontrar vulnerabilidades
  `HIGH` ou `CRITICAL`;
- adicionar um `.dockerignore` para evitar o envio de ambientes virtuais e
  arquivos locais para a imagem.

O propósito do repositório é acompanhar o ciclo de reconhecer um padrão
inseguro, aplicar uma correção verificável e automatizar a detecção no
pipeline. A remoção dos conflitos de merge e o alinhamento do pipeline com
Python 3.12 são avanços recentes; a correção das vulnerabilidades restantes
continua fazendo parte do exercício prático do LFD121.

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

