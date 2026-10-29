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

A única dependência de execução declarada atualmente é `bcrypt==4.2.1`, que o
código utiliza diretamente para o hash das senhas. Dependências não utilizadas
foram removidas para reduzir a superfície de ataque e o custo de manutenção.

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

| Prática estudada                   | Aplicação neste projeto                                                      | Evidência                                |
| ---------------------------------- | ---------------------------------------------------------------------------- | ---------------------------------------- |
| Não armazenar segredos no código   | `API_KEY` e `Senha_ADMIN_INICIAL` são obtidas por variáveis de ambiente      | `os.getenv()` em `app.py`                |
| Proteger credenciais               | A senha não é salva em texto puro; é gerado um salt e armazenado um hash     | `bcrypt.gensalt()` e `bcrypt.hashpw()`   |
| Validar entradas                   | O nome de usuário é validado quanto ao tipo, tamanho e caracteres permitidos | `validar_nome_usuario()`                 |
| Evitar injeção de SQL              | O nome do usuário é enviado como parâmetro, separado da instrução SQL        | `cursor.execute(query, (nome_usuario,))` |
| Automatizar a análise de segurança | O código e as dependências são analisados no CI                              | Semgrep e pip-audit                      |
| Reduzir riscos da imagem           | A imagem usa uma variante slim e executa como usuário não-root               | `dockerfile`                             |
| Verificar dependências e imagem    | Dependências Python e bibliotecas do container são examinadas                | pip-audit e Trivy                        |
| Aplicar shift left                 | As verificações acontecem em pushes e pull requests antes do deploy          | `.github/workflows/seguranca.yml`        |

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
- dependência de execução ainda precisa passar por revisão periódica de
  vulnerabilidades;
- política de exceções do Trivy ainda precisa ser definida para cada ambiente;
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

O passo do Trivy usa `exit-code: "1"` para que vulnerabilidades `HIGH` ou
`CRITICAL` façam o job falhar. Exceções devem ser documentadas e aprovadas
explicitamente, em vez de ignoradas silenciosamente.

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

Antes de considerar o laboratório funcional, é necessário:

- corrigir o nome da tabela na consulta de autenticação;
- manter a validação das variáveis obrigatórias sem valores padrão para
  segredos;
- garantir que as variáveis obrigatórias não tenham segredos padrão;
- revisar periodicamente a dependência fixada e os resultados do `pip-audit`;
- definir um processo formal para aprovar exceções do Trivy;
- evoluir os testes para cobrir autorização, sessões e limites de tentativa.

O valor principal deste repositório é mostrar o ciclo: reconhecer um padrão
inseguro, aplicar uma correção simples e verificável e automatizar a detecção
do problema no pipeline.

