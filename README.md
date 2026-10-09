# JurisHome - Sistema de Login Seguro

## Sobre o projeto

O JurisHome é um sistema de autenticação e autorização desenvolvido com Java 21, Spring Boot, Spring Security, Thymeleaf e MongoDB Atlas.

O projeto controla o cadastro, o acesso e as permissões dos usuários de uma aplicação jurídica. A organização em camadas mantém a segurança e as regras de negócio separadas da interface.

## Funcionalidades implementadas

- cadastro com validação de nome completo, nome de usuário, e-mail e senha;
- confirmação do cadastro por link temporário;
- login por nome de usuário ou e-mail;
- logout com invalidação da sessão;
- recuperação de senha por link temporário e de uso único;
- verificação em duas etapas com Google Authenticator;
- armazenamento de senhas com BCrypt;
- bloqueio da conta por 15 minutos após três tentativas incorretas;
- autorização baseada em três perfis de acesso;
- gerenciamento de contas e perfis pelo administrador;
- persistência de usuários e sessões no MongoDB;
- interface web construída com Thymeleaf;
- testes automatizados dos fluxos de autenticação e autorização.

## Tecnologias utilizadas

- Java 21
- Spring Boot 4.0.8
- Spring Security 7
- Spring Data MongoDB
- Spring Session MongoDB
- Thymeleaf
- Bean Validation
- Maven Wrapper
- MongoDB Atlas
- ZXing para geração local do QR Code

## Perfis de acesso

| Perfil | Permissões |
| --- | --- |
| `ROLE_USER` | painel e área do cliente |
| `ROLE_MODERATOR` | painel, área do cliente e área da equipe jurídica |
| `ROLE_ADMIN` | acesso completo e gerenciamento de usuários |

O cadastro público atribui somente `ROLE_USER`. A alteração de perfis é restrita ao administrador e validada no backend.

## Rotas protegidas

| Rota | Regra de acesso |
| --- | --- |
| `/`, `/login` e `/cadastro` | acesso público |
| `/cadastro/confirmar` e `/cadastro/reenviar` | acesso público |
| `/senha/esqueci` e `/senha/redefinir` | acesso público |
| `/2fa/configurar` e `/2fa/verificar` | usuário com senha validada |
| `/dashboard` | usuário autenticado |
| `/usuario/**` | usuário, moderador ou administrador |
| `/moderador/**` | moderador ou administrador |
| `/admin/**` | administrador |

As permissões são aplicadas pelo Spring Security. A interface exibe somente as áreas permitidas, mas a proteção principal permanece no servidor.

## Fluxo de autenticação

1. o usuário informa o nome de usuário ou e-mail e a senha;
2. o Spring Security valida a senha e o estado da conta;
3. no primeiro acesso, o sistema apresenta um QR Code para cadastro no Google Authenticator;
4. o usuário confirma o código de seis dígitos;
5. somente depois do segundo fator as áreas protegidas são liberadas.

Os códigos seguem o padrão TOTP, possuem seis dígitos e mudam a cada 30 segundos. A validação tolera uma diferença de até 60 segundos entre o relógio do celular e o servidor. Três códigos incorretos encerram a sessão e contam para o bloqueio temporário da conta. O administrador consegue redefinir o autenticador de outro usuário.

## Estrutura do projeto

```text
src/main/java/br/com/jurishome/auth/
|-- config/       configurações de segurança, sessão e aplicação
|-- domain/       documentos persistidos e perfis de acesso
|-- dto/          dados e validações dos formulários
|-- exception/    exceções das regras de negócio
|-- repository/   acesso ao MongoDB
|-- security/     tratamento de sucesso e falha no login
|-- service/      autenticação e regras de negócio
`-- web/          controllers e rotas MVC

src/main/resources/
|-- application.yml
|-- static/css/   estilos da interface
`-- templates/    páginas e fragmentos Thymeleaf
```

Os controllers recebem as requisições, os services executam as regras de negócio e os repositories realizam a persistência. Os DTOs impedem o vínculo direto dos formulários com os documentos do banco.

## Integração com MongoDB Atlas

A conexão é configurada pela variável de ambiente `MONGODB_URI`. Dessa forma, a credencial do banco não fica armazenada no código-fonte.

Configuração do cluster:

1. criar um cluster no MongoDB Atlas;
2. criar um usuário com permissão de leitura e escrita;
3. autorizar o endereço IP em **Network Access**;
4. copiar a URI disponível em **Connect > Drivers**;
5. definir a variável `MONGODB_URI` antes de executar a aplicação.

No PowerShell:

```powershell
$env:MONGODB_URI = "mongodb+srv://USUARIO:SENHA@CLUSTER.mongodb.net/jurishome?retryWrites=true&w=majority"
```

`USUARIO`, `SENHA` e `CLUSTER` representam os dados fornecidos pelo MongoDB Atlas. A URI real não deve ser adicionada ao repositório.

### Coleções utilizadas

| Coleção | Dados armazenados |
| --- | --- |
| `users` | nome completo, usuários, hash das senhas, configuração do autenticador, perfis, estado da conta e bloqueios |
| `sessions` | sessões HTTP gerenciadas pelo Spring Session |
| `email_verification_tokens` | tokens de confirmação de cadastro |
| `password_reset_tokens` | tokens de recuperação de senha |

Os campos `username` e `email` possuem índices únicos. As sessões e os tokens possuem expiração configurada no MongoDB.

## Configuração da conta administrativa

A conta administrativa inicial é criada pelas variáveis abaixo:

```powershell
$env:ADMIN_USERNAME = "administrador"
$env:ADMIN_EMAIL = "admin@jurishome.com.br"
$env:ADMIN_PASSWORD = "Defina-Uma-Senha-Forte-123!"
```

A senha aceita de 12 a 72 caracteres e exige letra maiúscula, letra minúscula, número e símbolo.

## Execução

Pré-requisitos:

- JDK 21;
- acesso ao cluster MongoDB Atlas;
- variável `MONGODB_URI` configurada;
- Google Authenticator instalado no celular para confirmar o segundo fator.

Na raiz do projeto, execute:

```powershell
.\mvnw.cmd spring-boot:run
```

A aplicação fica disponível em:

```text
http://localhost:8080
```

No ambiente local, os links de confirmação de cadastro e recuperação de senha são exibidos na própria página. Os tokens continuam sendo temporários, armazenados como hash e aceitos uma única vez.

## Decisões de segurança

- BCrypt com custo 12 para armazenamento das senhas;
- validação dos dados recebidos no backend;
- proteção CSRF mantida nos formulários;
- migração do identificador da sessão após a autenticação;
- cookies de sessão com `HttpOnly` e `SameSite=Lax`;
- mensagens genéricas para credenciais inválidas;
- bloqueio persistido depois de três falhas de login;
- segundo fator obrigatório com códigos TOTP compatíveis com Google Authenticator;
- QR Code gerado na própria aplicação, sem serviço externo;
- tokens aleatórios armazenados somente como hash SHA-256;
- invalidação das sessões após troca de senha, desativação ou alteração de perfil;
- proteção contra exclusão do próprio administrador e do último administrador ativo;
- cabeçalhos Content Security Policy e Referrer Policy;
- credenciais recebidas exclusivamente por variáveis de ambiente.

## Interface e separação de responsabilidades

As páginas utilizam fragmentos do Thymeleaf para compartilhar a estrutura visual. O layout está em `templates/fragments/layout.html`, os estilos gerais em `static/css/app.css` e a identidade visual do JurisHome em `static/css/themes/jurishome.css`.

Essa separação mantém HTML e CSS fora das regras de autenticação. Alterações visuais permanecem isoladas dos controllers, services, repositories e configurações do Spring Security.

## Testes

Execute a suíte com:

```powershell
.\mvnw.cmd clean test
```

Para gerar o arquivo executável:

```powershell
.\mvnw.cmd clean package
```

Para executar o arquivo gerado:

```powershell
java -jar target\jurishome-1.0.0.jar
```

A suíte contém 31 testes para cadastro, validação, duplicidade, hash de senha, login, segundo fator TOTP, tolerância controlada de horário, geração do QR Code, mensagens genéricas de erro, bloqueio por tentativas, autorização dos três perfis, CSRF, logout, persistência de usuários e sessões, recuperação de senha e operações administrativas.

## Arquivos de configuração

- `application.yml`: configura conexão, sessão, cookies, segurança e execução;
- `.env.example`: lista as variáveis de ambiente sem credenciais reais;
- `.gitignore`: impede o versionamento de `.env`, `target`, arquivos da IDE e logs.

