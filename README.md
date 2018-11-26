# Security P1G1

## Sumário
Nesta pasta encontra-se o código do projeto segurança.

## Pré-requesitos
```
$ python3 -m venv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
```

## Executar

### Configuração
#### Client
Para este processo ser executado corretamente é necessário indicar o caminho para a biblioteca **libpteidpkcs11.so**.
O caminho para esta biblioteca deve ser indicado no ficheiro ./client/config.ini

### Manualmente
Abrir 3 terminais e em cada terminal correr apenas uma vez:
```
$ source venv/bin/activate
```

Execute as aplicações pela seguinte ordem:

Terminal 1:
```
$ python3 -m security2018-p1g1.auction_repository.auction_repository
```

Terminal 2:
```
$ python3 -m security2018-p1g1.auction_manager.auction_manager
```

Terminal 3:
```
$ python3 -m security2018-p1g1.client.client
```
### Automaticamente
Foram criados tres scripts em bash para facilitar a execução dos processos.
Os scripts encontram-se na pasta bin e cada um deles ativa o virtual environment e executa o respetivo processo.
Basta executa-los pela seguinte ordem (em terminais diferentes):
1. ./auction_repository.sh
2. ./auction_manager.sh
3. ./client.sh

