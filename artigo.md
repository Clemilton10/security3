# Identity Server

[Home](./README.md) | [Alterações](./alteracoes.md) | [Instalações](./instalacoes.md) | [Artigo](./artigo.md)

## Original em inglês

- [https://www.scottbrady91.com/identity-server/getting-started-with-identityserver-4](https://www.scottbrady91.com/identity-server/getting-started-with-identityserver-4)

## Introdução ao IdentityServer4 e ao Duende IdentityServer

IdentityServer é o popular OSS OpenID Connect e OAuth framework para ASP.NET Core. Ele permite que seu site ASP.NET Core atue como um provedor OpenID e servidor de autorização OAuth, oferecendo proteção de logon único (SSO) e API pronta para uso. O IdentityServer cuida do suporte ao protocolo, mas a autenticação do usuário depende de você, o desenvolvedor.

Neste tutorial, você verá uma implementação do IdentityServer adicionada a um projeto Web básico, com exemplos mostrando como configurar aplicativos cliente, escopos de API e autenticação de usuário. Ao final deste tutorial, você terá uma implementação do IdentityServer em funcionamento, usando ASP.NET Identity, com um exemplo ASP.NET aplicativo cliente Core e API (recurso protegido).

Este artigo tem exemplos para IdentityServer4 e Duende IdentityServer (v5), visando o .NET Core 3.1 em diante. Você pode alternar entre o código IdentityServer4 e Duende IdentityServer à medida que avança no artigo.

## IdentityServer 3 vs IdentityServer 4

Após o lançamento do IdentityServer4 (aka. IDS4), o IdentityServer3 entrou no modo de manutenção, com apenas correções de segurança sendo lançadas. No entanto, em 2019, a Microsoft abandonou o suporte para as bibliotecas OWIN (Katana 3) nas quais o IdentityServer3 dependia e, como resultado, o suporte gratuito ao IdentityServer3 terminou.

Se você ainda estiver usando o IdentityServer3 (ou mesmo o IdentityServer2), eu recomendo que você migre para a versão mais recente do IdentityServer o mais rápido possível.

Existem algumas diferenças entre IdentityServer3 e IdentityServer4. Se você quiser saber mais, <details><summary>clique aqui</summary>

IdentityServer3 e IdentityServer4 são principalmente compatíveis. Normalmente, ambos implementam as mesmas especificações; ambos são provedores OpenID; no entanto, seus internos são quase completamente diferentes. Felizmente, quando você integra usando OpenID Connect ou OAuth, no caso do IdentityServer, você não está integrando a uma implementação, mas sim integrando usando as especificações OpenID Connect ou OAuth. Na minha experiência, o IdentityServer é uma das implementações menos opinativas dessas especificações por aí.

O IdentityServer foi projetado para ser executado como um componente auto-hospedado, o que era difícil de alcançar com o ASP.NET 4.x devido ao MVC ainda estar fortemente acoplado ao IIS e ao System.Web. Isso resultou em IdentityServer3 ter um mecanismo de exibição interno servido pelo componente katana. Com o IdentityServer4 agora em execução no ASP.NET Core, agora você pode usar qualquer tecnologia de interface do usuário que desejar e pode hospedar o IdentityServer em qualquer lugar que o ASP.NET Core possa executar. Isso também significa que agora você pode se integrar a formulários/sistemas de login existentes, permitindo atualizações in-loco.

O IdentityServer que era usado para integrar seu repositório de usuários também desapareceu, substituído por uma nova abstração de repositório de usuários na forma de e . Agora você mesmo deve implementar a autenticação do usuário (e isso é uma coisa boa). `IUserService` `IProfileService` `IResourceOwnerPasswordValidator`

Na minha experiência, muitas pessoas ainda estão usando o IdentityServer3 (eu até tive clientes que ainda usam o IdentityServer2). Minha recomendação é considerar seriamente a migração para a versão mais recente do IdentityServer assim que possível. Mas, admito, reescrever seu sistema de autenticação, em vez de criar novos recursos, pode ser difícil de vender para as partes interessadas.

</details>.

## IdentityServer4 vs Duende IdentityServer

A partir de 2021, o IdentityServer mudou para uma licença comercial e agora é conhecido como Duende IdentityServer (tipo de IdentityServer v5). O Duende IdentityServer ainda é OSS, mas a licença agora exige que a maioria das organizações compre uma licença do Duende.

O IdentityServer4 continuará a ter suporte durante a vida útil do .NET Core 3.1, que termina em dezembro de 2022. No entanto, para versões mais recentes do .NET, você deve Duende IdentityServer em vez disso.

No momento em que este artigo foi escrito (setembro de 2021), as bases de código IdentityServer4 e Duende IdentityServer são basicamente as mesmas; mas isso mudará com o tempo, especialmente à medida que o .NET lança mais versões LTS. Atualmente, os novos recursos do Duende incluem gerenciamento de chaves, carregamento dinâmico de provedores de identidade externos, indicadores de recursos OAuth e acesso a uma biblioteca de cliente BFF.

## Implementando o IdentityServer no ASP.NET Core e no .NET Core

Antes de iniciar este tutorial, verifique se você está usando a versão mais recente do ASP.NET Core e as ferramentas do .NET Core. Ao criar este tutorial, usei o .NET Core 3.1 e o JetBrains Rider (o Visual Studio é bom).

Você vai começar a criar seu IdentityServer como um aplicativo Web vazio, sem quaisquer dependências MVC ou Razor ou qualquer autenticação. Você pode criar isso usando o `dotnet new`

```sh
dotnet new web
```

Você pode obter o mesmo no Visual Studio, criando um projeto "Aplicativo Web ASP.NET Core" usando o modelo "Vazio". Apenas certifique-se de ativar HTTPS e não usar autenticação.

O restante deste tutorial assumirá que você está usando para sua solução IdentityServer. Isso pode ser configurado em seu arquivo ("Propriedades" no Visual Studio). `https://localhost:5000` em `launchSettings.json`

Agora, vamos adicionar o IdentityServer instalando-o a partir do NuGet. Ao criar este tutorial, usei o IdentityServer4 versão 4.1.2 e o Duende IdentityServer versão 5.2.2.

```sh
dotnet add package Duende.IdentityServer
```

Em seguida, vá para sua classe de inicialização, onde você pode começar a registrar dependências e conectar seu pipeline.

Em seu método, adicione o seguinte para registrar as dependências mínimas necessárias para IdentityServer: `ConfigureServices`

```csharp
services.AddIdentityServer(
  options => options.KeyManagement.Enabled = true)
    .AddInMemoryClients(new List<Client>())
    .AddInMemoryIdentityResources(new List<IdentityResource>())
    .AddInMemoryApiResources(new List<ApiResource>())
    .AddInMemoryApiScopes(new List<ApiScope>())
    .AddTestUsers(new List<TestUser>());
```

E, em seguida, atualize seu método para se parecer com o seguinte para permitir que o IdentityServer comece a lidar com solicitações OAuth e OpenID Connect: `Configure`

```csharp
public void Configure(IApplicationBuilder app)
{
    app.UseRouting();
    app.UseIdentityServer();
}
```

Com o código acima, você registrou o IdentityServer em seu contêiner de DI usando , usou um certificado de assinatura de demonstração com e usou armazenamentos voláteis na memória para seus clientes, recursos e usuários. Você não precisa ligar ao usar o Duende IdentityServer, pois o IdentityServer gerenciará as chaves de assinatura para você. `AddIdentityServer` `AddDeveloperSigningCredential` `AddDeveloperSigningCredential`

Ao usar o , você também está fazendo com que todos os dados temporários gerados sejam armazenados na memória. Você adicionará clientes, recursos e usuários reais em breve. `AddIdentityServer`

`UseIdentityServer` permite que o IdentityServer comece a manipular o roteamento para pontos de extremidade OAuth e OpenID Connect, como os pontos de extremidade de autorização e token.

Com essa configuração, você já pode executar o IdentityServer. Ele pode não ter interface do usuário, não suportar nenhum escopo e não ter usuários, mas você já pode começar a usá-lo! Confira o documento de descoberta do OpenID Connect em `/.well-known/openid-configuration`

## Documento de descoberta do OpenID Connect

O documento de descoberta do IdentityServer (carinhosamente conhecido como "disco doc") está disponível no caminho, de acordo com a especificação de descoberta do OpenID Connect. Este documento contém informações de metadados, tais como: `/.well-known/openid-configuration`

- localização de vários pontos de extremidade (por exemplo, o ponto de extremidade de autorização e o ponto de extremidade de token)
- local de suas chaves públicas (um conjunto de chaves da Web JSON (JWKS))
- Tipos de concessão que o provedor oferece suporte
- escopos que ele pode autorizar.

Ao ter esse documento padronizado, você habilita a possibilidade de integração automática e substituição automática de chaves.

## Credenciais de assinatura do IdentityServer

Suas credenciais de assinatura são chaves privadas usadas para assinar tokens. Isso permite que aplicativos cliente e recursos protegidos verifiquem se o conteúdo do token não foi alterado em trânsito e se o token foi criado pelo IdentityServer.

O IdentityServer usa a chave privada para criar assinaturas, enquanto outros aplicativos usam a chave pública correspondente para verificar a assinatura. Essas chaves públicas são acessíveis a aplicativos cliente por meio do documento de descoberta do OpenID Connect. `jwks_uri`

Quando você for criar e usar suas próprias credenciais de assinatura, faça isso usando uma ferramenta como OpenSSL ou o comando PowerShell. Você pode armazenar as chaves em um certificado X.509, mas não deve haver necessidade de ter o certificado emitido por uma CA Global. O IdentityServer está interessado apenas na chave privada aqui e os verificadores normalmente estão preocupados apenas com a chave pública. `New-SelfSignedCertificate`

Na verdade, com as versões mais recentes do IdentityServer, você não está mais restrito apenas a chaves RSA. Agora você pode [usar o ECDSA no IdentityServer](https://www.scottbrady91.com/identity-server/using-ecdsa-in-identityserver4).

## Clientes, recursos e usuários do IdentityServer

Agora que você tem o IdentityServer em funcionamento, vamos adicionar alguns dados a ele.

Primeiro, você precisa ter um repositório de aplicativos cliente que têm permissão para usar o IdentityServer, bem como os recursos protegidos que esses clientes podem usar e os usuários que podem se autenticar em seu sistema.

No momento, você está usando os armazenamentos na memória cujos registros aceitam uma coleção de suas respectivas entidades, que agora você pode preencher no código.

## Aplicativos cliente IdentityServer

O IdentityServer precisa saber quais aplicativos cliente têm permissão para usá-lo. Eu gosto de pensar nisso como uma lista de aplicativos que têm permissão para usar seu sistema; sua Lista de Controle de Acesso (ACL). Cada aplicativo cliente é então configurado para ter permissão apenas para fazer certas coisas; por exemplo, eles só podem pedir que os tokens sejam retornados para URLs específicos, ou eles só podem solicitar certas informações sobre o usuário. Eles têm acesso com escopo.

```csharp
internal class Clients
{
    public static IEnumerable<Client> Get()
    {
        return new List<Client>
        {
            new Client
            {
                ClientId = "oauthClient",
                ClientName = "Example client application using client credentials",
                AllowedGrantTypes = GrantTypes.ClientCredentials,
                ClientSecrets = new List<Secret> {new Secret("SuperSecretPassword".Sha256())}, // change me!
                AllowedScopes = new List<string> {"api1.read"}
            }
        };
    }
}
```

Aqui você está adicionando um cliente que usa o tipo de concessão de credenciais de cliente do OAuth. Esse tipo de concessão requer uma ID de cliente e um segredo para autorizar o acesso, com o segredo simplesmente sendo hashed usando um método de extensão fornecido pelo IdentityServer. Afinal, você nunca deve armazenar senhas (segredos compartilhados) em texto simples, e seus segredos em produção devem ter entropia suficiente para nunca serem adivinháveis. Os escopos permitidos são uma lista de permissões que esse cliente tem permissão para solicitar do IdentityServer. Neste exemplo, o único escopo permitido é api1.read, que você inicializará agora na forma de um recurso de API.

## Recursos do IdentityServer & escopos

Os escopos representam o que um aplicativo cliente tem permissão para fazer. Eles representam o escopo de acesso que mencionei antes. No IdentityServer, os escopos são normalmente modelados como recursos, que vêm em dois tipos: identidade e API.

Um recurso de identidade permite modelar um escopo que permitirá que um aplicativo cliente exiba um subconjunto de declarações sobre um usuário. Por exemplo, o escopo permite que o aplicativo veja declarações sobre o usuário, como nome e data de nascimento. `profile`

Um recurso de API permite modelar o acesso a um recurso protegido inteiro, uma API, com níveis de permissões individuais (escopos) aos quais um aplicativo cliente pode solicitar acesso.

```csharp
internal class Resources
{
    public static IEnumerable<IdentityResource> GetIdentityResources()
    {
        return new[]
        {
            new IdentityResources.OpenId(),
            new IdentityResources.Profile(),
            new IdentityResources.Email(),
            new IdentityResource
            {
                Name = "role",
                UserClaims = new List<string> {"role"}
            }
        };
    }

    public static IEnumerable<ApiResource> GetApiResources()
    {
        return new[]
        {
            new ApiResource
            {
                Name = "api1",
                DisplayName = "API #1",
                Description = "Allow the application to access API #1 on your behalf",
                Scopes = new List<string> {"api1.read", "api1.write"},
                ApiSecrets = new List<Secret> {new Secret("ScopeSecret".Sha256())}, // change me!
                UserClaims = new List<string> {"role"}
            }
        };
    }

	public static IEnumerable<ApiScope> GetApiScopes()
    {
        return new[]
        {
            new ApiScope("api1.read", "Read Access to API #1"),
			new ApiScope("api1.write", "Write Access to API #1")
        };
    }
}
```

## IdentityServer IdentityResources

Os três primeiros recursos de identidade representam alguns escopos padrão do OpenID Connect que você deseja que o IdentityServer suporte. Por exemplo, o escopo permite que as declarações e sejam retornadas. Você também está criando um recurso de identidade personalizado chamado que retorna quaisquer declarações para o usuário autenticado. `email` `email` `email_verified` `role` `role`

Uma dica rápida, o escopo é sempre necessário ao usar fluxos do OpenID Connect (onde você deseja receber um [token de identidade](https://www.scottbrady91.com/openid-connect/identity-tokens)). Você verá isso em ação em breve. `openid`

Você pode encontrar mais informações sobre esses escopos de identidade principais do OpenID Connect na [especificação do OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims).

## IdentityServer ApiResources e ApiScopes

Um recurso de API modela uma única API que o IdentityServer está protegendo. No OAuth, isso é conhecido como um "recurso protegido".

Um escopo de API é um nível de autorização individual em uma API que um aplicativo cliente tem permissão para solicitar. Por exemplo, um recurso de API pode ser , com os escopos , e . Os escopos de API podem ser refinados ou genéricos quanto você desejar. `adminapi` `adminapi.read` `adminapi.write` `adminapi.createuser`

Lembre-se, os escopos representam o que o usuário está autorizando o aplicativo cliente a fazer em seu nome. Isso não significa que o usuário tem permissão para executar uma ação.

Ao definir a propriedade, você garante que esses tipos de declaração serão adicionados a quaisquer tokens de acesso que tenham esse escopo (se o usuário tiver um valor para esse tipo, é claro). Nesse caso, você está garantindo que as declarações de função de um usuário serão adicionadas a quaisquer tokens de acesso autorizados a usar esse escopo. `UserClaims`

> ## Escopo vs. Recurso
>
> Os escopos OpenID Connect e OAuth sendo modelados como recursos é a alteração conceitual mais significativa entre o IdentityServer 3 e o IdentityServer 4. Na iteração mais recente, um recurso pode ter muitos escopos e um escopo pode pertencer a muitos recursos, mas um escopo não precisa necessariamente pertencer a um recurso.
>
> O escopo usado para solicitar tokens de atualização agora é suportado por padrão, com a autorização para usar esse escopo controlada pela propriedade Client . offline_accessAllowOfflineAccess
>
> Para ler mais sobre recursos e escopos de API no IdentityServer, recomendo verificar a documentação do IdentityServer4.

## Usuários de teste do IdentityServer

No lugar de um repositório de usuário completo, como ASP.NET Identity, você pode usar a classe de IdentityServer: `TestUsers`

```csharp
internal class Users
{
    public static List<TestUser> Get()
    {
        return new List<TestUser> {
            new TestUser {
                SubjectId = "5BE86359-073C-434B-AD2D-A3932222DABE",
                Username = "scott",
                Password = "password",
                Claims = new List<Claim> {
                    new Claim(JwtClaimTypes.Email, "scott@scottbrady91.com"),
                    new Claim(JwtClaimTypes.Role, "admin")
                }
            }
        };
    }
}
```

A declaração de assunto (ou sub) de um usuário é seu identificador exclusivo. Isso deve ser algo exclusivo do seu provedor de identidade que nunca mudará, ao contrário de dados voláteis, como um endereço de e-mail.

Com esses dados de teste, agora você pode atualizar seu contêiner de DI para ter a seguinte aparência:

```csharp
services.AddIdentityServer(
  options => options.KeyManagement.Enabled = true)
    .AddInMemoryClients(Clients.Get())
    .AddInMemoryIdentityResources(Resources.GetIdentityResources())
    .AddInMemoryApiResources(Resources.GetApiResources())
    .AddInMemoryApiScopes(Resources.GetApiScopes())
    .AddTestUsers(Users.Get())
```

Se você executar novamente o IdentityServer e visitar o documento de descoberta, verá que as seções e são preenchidas com base em seus recursos de identidade e escopos de API. `scopes_supported` `claims_supported`

## Funcionalidade OAuth

Para testar sua implementação, você pode pegar um token de acesso do IdentityServer usando o cliente OAuth que você configurou. Isso usará o fluxo de credenciais do cliente, o que significa que sua solicitação terá a seguinte aparência:

```sh
POST
http://localhost:5000/connect/token
	Body
		x-www-form-urlencoded
			grant_type		client_credentials
			scope			api1.read
			client_id		oauthClient
			client_secret	SuperSecretPassword
```

Que retorna uma resposta de token:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjA3MzdCRDU2MUU2MTExM0UzMTVFRDQ3QUM1MzBCRkI5IiwidHlwIjoiYXQrand0In0.eyJpc3MiOiJodHRwczovL2xvY2FsaG9zdDo1MDAwIiwibmJmIjoxNjMwMTY4OTY3LCJpYXQiOjE2MzAxNjg5NjcsImV4cCI6MTYzMDE3MjU2NywiYXVkIjoiYXBpMSIsInNjb3BlIjpbImFwaTEucmVhZCJdLCJjbGllbnRfaWQiOiJvYXV0aENsaWVudCIsImp0aSI6IkY0MzZGREY5OUU4Q0Y2QTREMkM0QzY5M0FCQTdDMEY4In0.HG-1bNAv5OQf_Vn8vI_-G5rK1ueQhsN_VSx_M78rU_n85hc1BH7Nt6p3MKeGPDy6YYed9krpGSgRwwB2GC-pdWM-o5X7JsVregZh1nCyOFBYvMYYQuDY2Pi3r49sXC6PrFvEvR4OzJ0phxuwFWvwG_IFVmYUaMalbpOdiLOgDl5R68gcwrQ-4NPYAdX_9tmLBLJZYFl5gpbhI5nwYDxGBIWpPk63oNIIYd9sVgMj7THdG_-tH5oV_eCT8MmsMK-_rOQ_o5GcmzwdMWvqn9enhf0995Rhf28ANBEEseEiWlKw_dCaRZ9OQE7Fp0GlCOtGmlpN6JN2UrKsKAS_m6dzAg",
  "expires_in": 3600,
  "token_type": "Bearer",
  "scope": "api1.read"
}
```

Se você levar esse token de acesso para [jwt.ms](https://jwt.ms/), verá que ele contém as seguintes declarações:

```json
// header
{
  "alg": "RS256",
  "kid": "0737BD561E61113E315ED47AC530BFB9",
  "typ": "at+jwt"
}

// payload
{
  "iss": "https://localhost:5000",
  "nbf": 1630168967,
  "iat": 1630168967,
  "exp": 1630172567,
  "aud": "api1",
  "scope": [
    "api1.read"
  ],
  "client_id": "oauthClient",
  "jti": "F436FDF99E8CF6A4D2C4C693ABA7C0F8"
}
```

## Protegendo uma API

Agora você pode usar esse token de acesso para acessar a API, protegido por sua implementação do IdentityServer.

Você pode criar rapidamente uma API usando a CLI do .NET, usando o modelo webapi:

```sh
dotnet new webapi
```

Para proteger a API, você pode usar o manipulador de autenticação JWT da Microsoft ou a implementação específica do IdentityServer. Eu prefiro a versão específica do IdentityServer porque ela define algumas opções padrão úteis e pode suportar tokens de referência e introspecção de token se você decidir se afastar dos JWTs.

```sh
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
```

Em seguida, você desejará adicionar o seguinte ao método da API: `ConfigureServices`

```csharp
services.AddAuthentication("Bearer")
    .AddJwtBearer("Bearer", options =>
    {
        options.Audience = "api1";
        options.Authority = "https://localhost:5000";
    });
```

Onde a autoridade é a URL do seu IdentityServer e o nome da audiência é o nome do recurso de API que o representa. Esse manipulador de autenticação buscará automaticamente o documento de descoberta do IdentityServer no primeiro uso.

Você também precisará adicionar o middleware de autenticação, atualizando seu método para ter a seguinte aparência: `Configure`

```csharp
public void Configure(IApplicationBuilder app)
{
    app.UseRouting();

    app.UseAuthentication();
    app.UseAuthorization();

    app.UseEndpoints(endpoints => endpoints.MapDefaultControllerRoute());
}
```

Em seguida, você pode exigir um token de acesso usando o em um de seus pontos de extremidade. `AuthorizeAttribute`

Para usar o token de acesso, basta anexá-lo a uma solicitação HTTP, usando o cabeçalho. Por exemplo: `Authorization`

```console
Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjA3MzdCRDU2MUU2MTExM0UzMTVFRDQ3QUM1MzBCRkI5IiwidHlwIjoiYXQrand0In0.eyJpc3MiOiJodHRwczovL2xvY2FsaG9zdDo1MDAwIiwibmJmIjoxNjMwMTY4OTY3LCJpYXQiOjE2MzAxNjg5NjcsImV4cCI6MTYzMDE3MjU2NywiYXVkIjoiYXBpMSIsInNjb3BlIjpbImFwaTEucmVhZCJdLCJjbGllbnRfaWQiOiJvYXV0aENsaWVudCIsImp0aSI6IkY0MzZGREY5OUU4Q0Y2QTREMkM0QzY5M0FCQTdDMEY4In0.HG-1bNAv5OQf_Vn8vI_-G5rK1ueQhsN_VSx_M78rU_n85hc1BH7Nt6p3MKeGPDy6YYed9krpGSgRwwB2GC-pdWM-o5X7JsVregZh1nCyOFBYvMYYQuDY2Pi3r49sXC6PrFvEvR4OzJ0phxuwFWvwG_IFVmYUaMalbpOdiLOgDl5R68gcwrQ-4NPYAdX_9tmLBLJZYFl5gpbhI5nwYDxGBIWpPk63oNIIYd9sVgMj7THdG_-tH5oV_eCT8MmsMK-_rOQ_o5GcmzwdMWvqn9enhf0995Rhf28ANBEEseEiWlKw_dCaRZ9OQE7Fp0GlCOtGmlpN6JN2UrKsKAS_m6dzAg
```

## Adicionando uma interface do usuário para autenticação do usuário

Até agora, o IdentityServer estava sendo executado sem uma interface do usuário. Vamos mudar isso puxando a interface do usuário de início rápido do GitHub que usa o MVC do ASP.NET Core.

Para baixar a interface do usuário do QuickStart, copie todas as pastas do repositório para o projeto ou use o comando PowerShell ou curl do Leiame do repositório (novamente, enquanto estiver dentro da pasta do projeto). Por exemplo:

```powershell
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/DuendeSoftware/IdentityServer.Quickstart.UI/main/getmain.ps1'))
```

- [IdentityServer4 Quickstart UI](https://github.com/IdentityServer/IdentityServer4.Quickstart.UI#quickstart-ui-for-identityserver4)
- [Duende IdentityServer Quickstart UI](https://github.com/DuendeSoftware/IdentityServer.Quickstart.UI)

Para aproveitar esses novos controladores e exibições, você precisará adicionar o seguinte ao seu método: `ConfigureServices`

```csharp
services.AddControllersWithViews();
```

E, em seguida, atualize seu método para se parecer com o seguinte, adicionando o middleware para arquivos estáticos, autorização e pontos de extremidade.`Configure`

```chsarp
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    app.UseStaticFiles();
    app.UseRouting();

    app.UseIdentityServer();
    app.UseAuthorization();

    app.UseEndpoints(endpoints => endpoints.MapDefaultControllerRoute());
}
```

Agora, quando você executa o projeto, supondo que você está executando no modo de desenvolvedor, você deve obter uma tela inicial. Viva! Agora que você tem uma interface do usuário, agora você pode começar a autenticar usuários.

<img src="001.webp" />

## Integrando um aplicativo MVC do ASP.NET Core com o IdentityServer

Para demonstrar a autenticação usando o OpenID Connect, você precisará criar outro aplicativo Web e configurá-lo como um aplicativo cliente no IdentityServer.

Vamos começar adicionando uma nova entrada de cliente no IdentityServer:

```csharp
new Client
{
    ClientId = "oidcClient",
    ClientName = "Example Client Application",
    ClientSecrets = new List<Secret> {new Secret("SuperSecretPassword".Sha256())}, // change me!

    AllowedGrantTypes = GrantTypes.Code,
    RedirectUris = new List<string> {"https://localhost:5002/signin-oidc"},
    AllowedScopes = new List<string>
    {
        IdentityServerConstants.StandardScopes.OpenId,
        IdentityServerConstants.StandardScopes.Profile,
        IdentityServerConstants.StandardScopes.Email,
        "role",
        "api1.read"
    },

    RequirePkce = true,
    AllowPlainTextPkce = false
}
```

Essa configuração adiciona um novo aplicativo cliente que usa o fluxo recomendado para aplicativos Web do lado do servidor: o fluxo de código de autorização com PKCE (Proof-Key for Code Exchange). Para esse cliente, você também definiu um URI de redirecionamento. Como esse fluxo ocorre por meio do navegador, o IdentityServer deve conhecer uma lista permitida de URLs para enviar o usuário de volta, assim que a autenticação do usuário e a autorização do cliente forem concluídas; para quais URLs ele pode retornar o resultado da autorização.

## Um aplicativo cliente MVC do ASP.NET Core

Agora você pode criar o próprio aplicativo cliente. Para isso, você precisará de outro site ASP.NET Core, desta vez usando o modelo, e novamente, sem autenticação. `mvc`

```sh
dotnet new mvc
```

Antes de adicionar um esquema de autenticação remota, como o OpenID Connect, você precisará adicionar um esquema de autenticação local, um cookie, que você pode adicionar ao seu método: `ConfigureServices`

```csharp
services.AddAuthentication(options =>
    {
        options.DefaultScheme = "cookie";
    })
    .AddCookie("cookie");
```

Isso diz ao seu aplicativo para usar a autenticação de cookies para tudo (o ). Então, se você chamar entrar, sair, desafiar, etc., então este é o esquema que será usado. Esse cookie local é necessário porque, mesmo que você esteja usando o IdentityServer para autenticar o usuário e criar uma sessão de logon único (SSO), cada aplicativo cliente individual manterá sua própria sessão de vida mais curta. `DefaultScheme`

Agora você pode atualizar sua configuração de autenticação para usar o OpenID Connect para descobrir quem é o usuário.

Primeiro, instale o pacote NuGet de autenticação do OpenID Connect:

```sh
dotnet add package Microsoft.AspNetCore.Authentication.OpenIdConnect
```

E, em seguida, você pode atualizar sua configuração de autenticação para ter a seguinte aparência:

```csharp
services.AddAuthentication(options =>
    {
        options.DefaultScheme = "cookie";
        options.DefaultChallengeScheme = "oidc";
    })
    .AddCookie("cookie")
    .AddOpenIdConnect("oidc", options =>
    {
	    options.Authority = "https://localhost:5000";
        options.ClientId = "oidcClient";
        options.ClientSecret = "SuperSecretPassword";

        options.ResponseType = "code";
        options.UsePkce = true;
        options.ResponseMode = "query";

        // options.CallbackPath = "/signin-oidc"; // default redirect URI

        // options.Scope.Add("oidc"); // default scope
        // options.Scope.Add("profile"); // default scope
        options.Scope.Add("api1.read");
        options.SaveTokens = true;
    });
```

Por padrão, o manipulador do ASP.NET Core OpenID Connect usará o fluxo implícito com o modo de pós-resposta do formulário. O fluxo implícito está em processo de ser preterido, e o formulário de resposta pós-publicação está se tornando não confiável graças às políticas de cookies de terceiros 3rd que estão sendo implementadas pelos navegadores. Como resultado, você os atualizou para usar o fluxo de código de autorização, PKCE e o modo de resposta de cadeia de caracteres de consulta.

> `UsePkce` é uma configuração relativamente nova no ASP.NET Core, confira meus outros artigos se você precisar implementar PKCE em aplicativos Web .NET [Core 2.1](https://www.scottbrady91.com/openid-connect/aspnet-core-using-proof-key-for-code-exchange-pkce) ou [.NET Framework](https://www.scottbrady91.com/aspnet/refreshing-your-legacy-aspnet-identityserver-client-applications).

Também mostrei algumas das configurações padrão usadas pelo manipulador de autenticação do OpenID Connect. Por padrão, a URL de redirecionamento usará o caminho. Tudo bem; no entanto, você precisará adicionar um caminho de retorno de chamada exclusivo para cada manipulador de autenticação que você tem em seu aplicativo. ASP.NET Core também adiciona os escopos oidc e de perfil que você pode limpar e/ou adicionar escopos extras, se necessário. faz com que os tokens de identidade e acesso sejam salvos, acessíveis usando código como . `/signin-oidc` `SaveTokens` `HttpConect.GetTokenAsync("access_token")`

Para que o caminho de retorno de chamada funcione, você precisará atualizar novamente o método Configure para chamar o middleware de autenticação ASP.NET Core:

```csharp
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    app.UseStaticFiles();
    app.UseRouting();

    app.UseAuthentication();
    app.UseAuthorization();

    app.UseEndpoints(endpoints => endpoints.MapDefaultControllerRoute());
}
```

E, novamente, adicione a uma ação do controlador para autenticar o usuário usando um cookie ou desafiá-lo via oidc. `AuthorizationAttribute`

```csharp
[Authorize]
public IActionResult Privacy() => View();
```

Na próxima vez que você executar o aplicativo e selecionar a página Privacidade, receberá um 401 não autorizado. Isso, por sua vez, será tratado pelo seu (seu manipulador de autenticação OpenID Connect), que o redirecionará para o ponto de extremidade de autorização do IdentityServer. `DefaultChallengeScheme`

<img src="002.webp" />

Após o login bem-sucedido, você será redirecionado de volta para o URI de redirecionamento do aplicativo cliente, será conectado usando seu cookie local e, em seguida, redirecionado de volta para a página que você estava tentando acessar (a página de privacidade). Isso é tudo o que é necessário para conectar um aplicativo cliente OpenID Connect simples no ASP.NET Core!

A partir do IdentityServer4 v4, a página de consentimento OAuth não está mais habilitada por padrão. Se você estiver lidando com aplicativos cliente de terceiros ou recursos protegidos, recomendo que você reative isso para seus aplicativos.

> ## Tipo de concessão de credenciais de senha do proprietário do recurso (ROPC)
>
> Em algum momento, você será perguntado por que a página de login não pode ser hospedada no aplicativo cliente, ou talvez você tenha alguém em uma equipe de UX gritando com você por pedir que eles usem um navegador da Web para autenticar o usuário.
>
> Claro, você poderia conseguir isso usando o tipo de concessão ROPC/senha; no entanto, esse é um antipadrão de segurança e esse tipo de concessão só está incluído na especificação OAuth 2.0 para ajudar aplicativos herdados. São aplicações consideradas legadas em 2012...
>
> O ROPC agora foi removido como parte do OAuth 2.1, mas para uma gravação completa de tudo o que está errado com o tipo de concessão Proprietário do Recurso, confira meu artigo Por que o Tipo de Concessão de Credenciais de Senha do Proprietário do Recurso não é Autenticação nem Adequado para Aplicativos Modernos.

## IdentityServer com Entity Framework Core

Atualmente, você está usando armazenamentos na memória que, como observei antes, são adequados apenas para fins de demonstração ou, no máximo, implementações muito leves. Idealmente, você gostaria de mover seus vários armazenamentos para um banco de dados persistente que não será apagado em cada implantação ou exigir uma alteração de código para adicionar uma nova entrada.

O IdentityServer tem um pacote Entity Framework (EF) Core que você pode usar para implementar repositórios de cliente, recurso, escopo e concessão persistente usando qualquer provedor de banco de dados relacional EF Core.

Para este tutorial, você usará o SQL Server (SQL Express ou Banco de Dados Local fará), portanto, precisará dos seguintes pacotes nuget:

```csharp
dotnet add package Duende.IdentityServer.EntityFramework
dotnet add package Microsoft.EntityFrameworkCore.SqlServer
```

Se você não quiser usar a biblioteca do Entity Framework do IdentityServer, precisará [criar sua própria camada de armazenamento do IdentityServer](https://www.scottbrady91.com/identity-server/creating-your-own-identityserver4-storage-library).

## Armazenando concessões persistentes usando o repositório operacional

O armazenamento de concessão persistente mantém dados temporários, como consentimento, tokens de referência, tokens de atualização, códigos de dispositivo, códigos de autorização e muito mais. Sem um armazenamento persistente para esses dados, você não poderá balancear a carga do IdentityServer de forma confiável.

Para usar o armazenamento padrão do Entity Framework do IdentityServer, primeiro você precisará obter uma cadeia de conexão e definir o assembly de migrações:

```csharp
// using local db (assumes Visual Studio has been installed)
const string connectionString = @"Data Source=(LocalDb)\MSSQLLocalDB;database=Test.IdentityServer.EntityFramework;trusted_connection=yes;";
var migrationsAssembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;
```

Em seguida, você pode adicionar suporte para o repositório de concessão persistente atualizando sua chamada para: `AddIdentityServer`

```csharp
AddOperationalStore(options => options.ConfigureDbContext =
    builder => builder.UseSqlServer(
        connectionString,
        sqlOptions => sqlOptions.MigrationsAssembly(migrationsAssembly)))
```

Nesse caso, você está definindo o assembly para armazenar suas migrações do EF como o assembly atual. Isso é necessário para direcionar DbContexts não localizados em seu projeto de hospedagem (neste caso, está em um pacote nuget) e nos permite executar migrações EF. Caso contrário, você será recebido com uma exceção com uma mensagem como:

```console
Your target project 'Project.Host' doesn't match your migrations assembly 'Project.BusinessLogic'. Either change your target project or change your migrations assembly. Change your migrations assembly by using DbContextOptionsBuilder. E.g. options.UseSqlServer(connection, b => b.MigrationsAssembly("Project.Host")). By default, the migrations assembly is the assembly containing the DbContext.

Change your target project to the migrations project by using the Package Manager Console's Default project drop-down list, or by executing "dotnet ef" from the directory containing the migrations project.
```

## Armazenando clientes e escopos do IdentityServer usando o repositório de configuração

Para adicionar armazenamento persistente para seu escopo e armazenamentos de clientes, você precisará de algo semelhante, desta vez substituindo as chamadas para , , e : `AddInMemoryClients` `AddInMemoryIdentityResources` `AddInMemoryApiScopes` `AddInMemoryApiResources`

```csharp
AddConfigurationStore(options => options.ConfigureDbContext =
    builder => builder.UseSqlServer(
        connectionString,
        sqlOptions => sqlOptions.MigrationsAssembly(migrationsAssembly)))
```

Esses registros também adicionam um serviço de política CORS que se inicializa a partir de dados em seus registros de cliente. Eu recomendo usar este serviço CORS. Não permita apenas todas as origens.

## Executando as migrações do IdentityServer EF

Para executar migrações do EF, você precisará das [ferramentas do EF Core instaladas](https://learn.microsoft.com/en-us/ef/core/get-started/overview/install#get-the-net-core-cli-tools) e do pacote `Microsoft.EntityFrameworkCore.Design` instalado em seu projeto:

```csharp
dotnet add package Microsoft.EntityFrameworkCore.Design
```

Depois disso, você pode criar suas migrações usando:

```sh
dotnet ef migrations add InitialIdentityServerMigration -c PersistedGrantDbContext
dotnet ef migrations add InitialIdentityServerMigration -c ConfigurationDbContext
```

Em seguida, você pode criar seus bancos de dados chamando dotnet ef database update em cada um dos contextos de banco de dados:

```sh
dotnet ef database update -c PersistedGrantDbContext
dotnet ef database update -c ConfigurationDbContext
```

> Para criar programaticamente clientes e recursos usando a configuração usada anteriormente, confira o método no [repositório GitHub deste artigo](https://github.com/scottbrady91/IdentityServer4-Example/blob/master/IdentityProvider/Startup.cs#L66). `InitializeDbTestData`

## IdentityServer com identidade ASP.NET Core

Para adicionar um armazenamento persistente para os usuários, o IdentityServer oferece integração pronta para uso para ASP.NET Core Identity (também conhecido como ASP.NET Identity 3). ASP.NET Identity inclui os recursos básicos necessários para implementar um sistema de autenticação de usuário pronto para produção, incluindo hash de senha, redefinição de senha e funcionalidade de bloqueio.

Este tutorial usará a implementação do Entity Framework Core dos repositórios de usuário e funções ASP.NET, o que significa que você precisará dos seguintes pacotes NuGet:

```sh
dotnet add package Duende.IdentityServer.AspNetIdentity
dotnet add package Microsoft.AspNetCore.Identity.EntityFrameworkCore
dotnet add package Microsoft.EntityFrameworkCore.SqlServer
```

Em seguida, você precisará criar um DbContext que herde ASP.NET Identity's e substituir o construtor para usar uma versão não genérica do . Isso ocorre porque só tem um construtor aceitando o genérico que, quando você está registrando vários DbContexts, resulta em um arquivo . Seria ótimo se essa cerimônia fosse [um dia tornada desnecessária](https://github.com/aspnet/Identity/issues/962). `IdentityDbContext` `DbContextOptions` `IdentityDbContext` `DbContextOptions` `InvalidOperationException`

```csharp
public class ApplicationDbContext : IdentityDbContext {
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }
}
```

Com essas bibliotecas instaladas e seu novo DbContext, agora você pode se registrar e depois precisa adicionar um registro para o ASP.NET Identity DbContext ao seu método. Esses registros devem ser feitos antes dos registros do IdentityServer. `ConfigureServices`

```csharp
services.AddDbContext<ApplicationDbContext>(builder =>
    builder.UseSqlServer(connectionString, sqlOptions => sqlOptions.MigrationsAssembly(migrationsAssembly)));

services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>();
```

> É importante saber que a chamada mudará o esquema de cookies padrão do seu aplicativo para . `AddIdentity` `IdentityConstants.ApplicationScheme`

Em seguida, você pode configurar o código interno do IdentityServer para usar ASP.NET Identity substituindo a chamada para: `AddTestUsers`

```csharp
AddAspNetIdentity<IdentityUser>()
```

Em um nível alto, essa chamada faz o seguinte:

- Adiciona um serviço de perfil compatível com ASP.NET Identity (como o IdentityServer gerou declarações de usuário)
- Adiciona uma implementação estendida do ASP.NET Identity (como o ASP.NET Identity transforma um objeto de usuário em declarações)IUserClaimsPrincipalFactory
- Configura o IdentityServer para usar os cookies do ASP.NET Identity e ajusta esses cookies para serem adequados para o OpenID Connect

Você também precisará de migrações de banco de dados para esse contexto, usando:

```sh
dotnet ef migrations add InitialIdentityServerMigration -c ApplicationDbContext
dotnet ef database update -c ApplicationDbContext
```

Isso é tudo o que é necessário para conectar o próprio IdentityServer para usar ASP.NET Core Identity, mas, infelizmente, a interface do usuário de início rápido que você baixou anteriormente não funcionará mais corretamente, pois ainda está usando um arquivo . No entanto, você pode modificar a interface do usuário do QuickStart para trabalhar com ASP.NET identidade principal substituindo algum código. `TestUserStore`

Este tutorial usará as identidades ASP.NET durante a autenticação. O atende à maioria dos casos de uso básicos, mas se você tiver quaisquer requisitos complexos de autenticação de usuário ou quiser maior controle sobre a experiência do usuário, recomendo usar ASP.NET Identity's em vez disso. `SignInManager` `SignInManager` `UserManager`

Comecemos pelo . Primeiro, você precisará alterar o construtor para aceitar o ASP.NET Identity , em vez do atual . Seu construtor agora deve ter a seguinte aparência: `AccountController` `SignInManager` `TestUserStore`

```csharp
private readonly IIdentityServerInteractionService _interaction;
private readonly IClientStore _clientStore;
private readonly IAuthenticationSchemeProvider _schemeProvider;
private readonly IEventService _events;
private readonly SignInManager<IdentityUser> _signInManager;

public AccountController(
    IIdentityServerInteractionService interaction,
    IClientStore clientStore,
    IAuthenticationSchemeProvider schemeProvider,
    IEventService events,
    SignInManager<IdentityUser> signInManager)
{
    _interaction = interaction;
    _clientStore = clientStore;
    _schemeProvider = schemeProvider;
    _events = events;

    _signInManager = signInManager;
}
```

Ao remover o , você deve ver que quebrou um único método: . Recomendo alterar o bloco de validação com falha para o seguinte: `TestUserStoreLogin`

# Login

<details><summary>

## Antes

</summary>

```csharp
// validate username/password against in-memory store
if (_users.ValidateCredentials(model.Username, model.Password))
{
    var user = _users.FindByUsername(model.Username);
    await _events.RaiseAsync(new UserLoginSuccessEvent(user.Username, user.SubjectId, user.Username, clientId: context?.Client.ClientId));

    // only set explicit expiration here if user chooses "remember me".
    // otherwise we rely upon expiration configured in cookie middleware.
    AuthenticationProperties props = null;
    if (AccountOptions.AllowRememberLogin && model.RememberLogin)
    {
        props = new AuthenticationProperties
        {
            IsPersistent = true,
            ExpiresUtc = DateTimeOffset.UtcNow.Add(AccountOptions.RememberMeLoginDuration)
        };
    };

    // issue authentication cookie with subject ID and username
    var isuser = new IdentityServerUser(user.SubjectId)
    {
        DisplayName = user.Username
    };

    await HttpContext.SignInAsync(isuser, props);

    // TODO: existing return URL handling...
}
```

</details>

<details><summary>

## Depois

</summary>

```csharp
// find user by username
var user = await _signInManager.UserManager.FindByNameAsync(model.Username);

// validate username/password using ASP.NET Identity
if (user != null && (await _signInManager.CheckPasswordSignInAsync(user, model.Password, true)) == SignInResult.Success)
{
    await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName, clientId: context?.Client.ClientId));

    // only set explicit expiration here if user chooses "remember me".
    // otherwise we rely upon expiration configured in cookie middleware.
    AuthenticationProperties props = null;
    if (AccountOptions.AllowRememberLogin && model.RememberLogin)
    {
        props = new AuthenticationProperties
        {
            IsPersistent = true,
            ExpiresUtc = DateTimeOffset.UtcNow.Add(AccountOptions.RememberMeLoginDuration)
        };
    };

    // issue authentication cookie with subject ID and username
    var isuser = new IdentityServerUser(user.Id)
    {
        DisplayName = user.UserName
    };

    await HttpContext.SignInAsync(isuser, props);

    // TODO: existing return URL handling...
}
```

</details>

Você precisará fazer algo semelhante no ExternalController, para vinculação e provisionamento de conta ao usar um provedor de identidade externo, como o Google ou o Azure AD.

# FindUserFromExternalProvider

<details><summary>

## Antes

</summary>

```csharp
var user = _users.FindByExternalProvider(provider, providerUserId);
```

</details>
<details><summary>

## Depois

</summary>

```csharp
var user = await _userManager.FindByLoginAsync(provider, providerUserId);
```

</details>

# AutoProvisionUser

<details><summary>

## Antes

</summary>

```csharp
var user = _users.AutoProvisionUser(provider, providerUserId, claims.ToList());
```

</details>
<details><summary>

## Depois

</summary>

```csharp
// create dummy internal account (you can do something more complex)
var user = new IdentityUser(Guid.NewGuid().ToString());
await _userManager.CreateAsync(user);

// add external user ID to new account
await _userManager.AddLoginAsync(user, new UserLoginInfo(provider, providerUserId, provider));
```

</details>

Você deve ser capaz de executar com isso e começar a ajustar a interface do usuário do QuickStart para atender às suas necessidades de negócios. Se você estiver preso, confira o [exemplo concluído para este tutorial no GitHub](https://github.com/scottbrady91/IdentityServer4-Example).

## Registro de usuário e redefinição de senha

Este tutorial trouxe apenas o uso básico do ASP.NET Core Identity. Para recursos como registro de usuário e redefinição de senha, não há nada específico do IdentityServer que você precise fazer. Basta seguir o uso regular do ASP.NET Identity!

Se você é novo no ASP.NET Identity, confira meu curso Pluralsight para um mergulho profundo na biblioteca.

## Próximos passos

Este tutorial abordou os conceitos básicos do IdentityServer e mostrou como usá-lo para proteger um aplicativo Web e uma API do ASP.NET Core. Isso deve ser suficiente para você começar, mas antes de entrar em produção, não se esqueça de abordar os pontos listados na [documentação de implantação](https://identityserver4.readthedocs.io/en/latest/topics/deployment.html).

Para casos de uso mais avançados, confira alguns dos meus outros artigos para aprender a:

- [Escolha a arquitetura certa para proteger seu SPA](https://www.scottbrady91.com/oauth/cheat-sheet-oauth-for-browser-based-applications)
- [Usando segredos assimétricos para autenticação de cliente (não há mais segredos compartilhados!)](https://www.scottbrady91.com/oauth/removing-shared-secrets-for-oauth-client-authentication)
- [Manipular a autorização do gateway de API e a comunicação API para API](https://www.scottbrady91.com/oauth/delegation-patterns-for-oauth-20)
- [Terceirizando a assinatura de token para o Cofre de Chaves do Azure](https://www.scottbrady91.com/identity-server/outsourcing-identityserver4-token-signing-to-azure-key-vault)
