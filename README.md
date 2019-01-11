# Security P1G1

## Sumário
Nesta pasta encontra-se o código do projeto segurança.

## Estrutura
Root
|
+--bin
|
+--src
|
+--README.md

## Base de Dados

### Auction Manager

#### Tabela para mapear leilões a utilizadores

|  Columns   |       Types      |
|------------|------------------|
| cc         | **TEXT (PK)**    |
| auction_id | **INTEGER (PK)** |

#### Tabela para guardar chaves dos utilizadores

|  Columns   |       Types      |
|------------|------------------|
| cc         | **TEXT (PK)**    |
| auction_id | **INTEGER (PK)** |
| cert       | TEXT             |
| key        | TEXT             |

### Auction Repository

#### Tabela para os leilões

| Columns  |       Types      |
|----------|------------------|
| id       | **INTEGER (PK)** |
| title    | TEXT             |
| desc     | TEXT             |
| type     | INTEGER          |
| subtype  | INTEGER          |
| duration | INTEGER          |
| start    | DATETIME         |
| stop     | DATETIME         |
| expires  | INTEGER          |
| blimit   | INTEGER          |
| open     | INTEGER (1)      |

## Pré-requesitos
Os pré-requisitos podem ser instalados manualmente.
Dentro da pasta src:

```
$ python3 -m venv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
```
Ou através de um script que prepara e executa o projecto:

```
$ ./bin/build_run.sh
```

## Executar

### Manualmente
Abrir 3 terminais e em cada terminal correr apenas uma vez:
```
$ source venv/bin/activate
```

Execute as aplicações pela seguinte ordem:

Terminal 1:
```
$ python3 -m src.auction_repository.auction_repository
```

Terminal 2:
```
$ python3 -m src.auction_manager.auction_manager
```

Terminal 3:
```
$ python3 -m src.client.client
```
### Automaticamente
Foram criados 3 scripts em bash para facilitar a execução dos 3 processos.
Os scripts encontram-se na pasta bin e cada um deles ativa o virtual environment e executa o respetivo processo.
Basta executa-los pela seguinte ordem (em terminais diferentes):
1. ./bin/auction_repository.sh
2. ./bin/auction_manager.sh
3. ./bin/client.sh

Em alternativa basta executar apenas o script ./bin/build_run.sh

