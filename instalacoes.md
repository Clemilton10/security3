# Identity Server

[Home](./README.md) | [Alterações](./alteracoes.md) | [Instalações](./instalacoes.md) | [Artigo](./artigo.md)

# Criar projeto vazio

```sh
mkdir security2
cd security2
dotnet new sln -n security
```

# Criar aplicação console

```sh
dotnet new console -n sec_console_get
dotnet sln add sec_console_get
```

GET - Program.cs

```csharp
class Program
{
	static async Task Main()
	{
		string apiUrl = "http://localhost:5000/";
		using (var httpClient = new HttpClient())
		{
			var response = await httpClient.GetAsync(apiUrl);
			if (response.IsSuccessStatusCode)
			{
				var content = await response.Content.ReadAsStringAsync();
				Console.WriteLine($"Resposta: {content}");
			}
			else
			{
				Console.WriteLine($"Erro na solicitação: {response.StatusCode}");
			}
		}
	}
}
```

```sh
dotnet new console -n sec_console_post_1
dotnet sln add sec_console_post_1
```

POST1 - Program.cs

```csharp
class Program
{
	static async Task Main()
	{
		string tokenEndpoint = "http://localhost:5000/connect/token";
		string clientId = "rangel";
		string clientSecret = "rangel@#$";
		string scope = "api1.read";

		string requestBody = $"grant_type=client_credentials&scope={scope}&client_id={clientId}&client_secret={clientSecret}";
		using (var httpClient = new HttpClient())
		{
			var content = new StringContent(
				requestBody,
				System.Text.Encoding.UTF8,
				"application/x-www-form-urlencoded"
			);

			var response = await httpClient.PostAsync(tokenEndpoint, content);

			if (response.IsSuccessStatusCode)
			{
				var accessToken = await response.Content.ReadAsStringAsync();
				Console.WriteLine($"Token de Acesso: {accessToken}");
			}
			else
			{
				Console.WriteLine($"Erro na solicitação: {response.StatusCode}");
			}
		}
	}
}
```

```sh
dotnet new console -n sec_console_post_2
dotnet sln add sec_console_post_2
```

POST2 - Program.cs

```csharp
class Program
{
	static async Task Main()
	{
		string tokenEndpoint = "http://localhost:5000/connect/token";
		string clientId = "rangel";
		string clientSecret = "rangel@#$";
		string scope = "api1.read";

		var content = new FormUrlEncodedContent(new[]
		{
			new KeyValuePair<string, string>("grant_type", "client_credentials"),
			new KeyValuePair<string, string>("scope", scope),
			new KeyValuePair<string, string>("client_id", clientId),
			new KeyValuePair<string, string>("client_secret", clientSecret),
		});

		using (var httpClient = new HttpClient())
		{
			var response = await httpClient.PostAsync(tokenEndpoint, content);
			if (response.IsSuccessStatusCode)
			{
				var accessToken = await response.Content.ReadAsStringAsync();
				Console.WriteLine($"Token de Acesso: {accessToken}");
			}
			else
			{
				Console.WriteLine($"Erro na solicitação: {response.StatusCode}");
			}
		}
	}
}

```

# Security

```sh
# Visual Studio - Aplicativo Web ASP.NET Core
dotnet new web --no-https -f net6.0 -n security

dotnet sln add security/security.csproj
cd security

dotnet add package IdentityServer4 --version 4.1.2
```

Clients.cs

```csharp
using IdentityServer4.Models;

internal class Clients
{
	public static IEnumerable<Client> Get()
	{
		return new List<Client>
		{
			new Client
			{
				ClientId = "rangelid",
				ClientName = "rangelname",
				AllowedGrantTypes = GrantTypes.ClientCredentials,
				ClientSecrets = new List<Secret> {new Secret("rangelsecret".Sha256())},
                AllowedScopes = new List<string> {"api1.read"}
			}
		};
	}
}
```

Resources.cs

```csharp
using IdentityServer4.Models;

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

Users.cs

```csharp
using IdentityModel;
using IdentityServer4.Test;
using System.Security.Claims;

internal class Users
{
	public static List<TestUser> Get()
	{
		return new List<TestUser> {
			new TestUser {
				SubjectId = "5BE86359-073C-434B-AD2D-A3932222DABE",
				Username = "clemas",
				Password = "123456",
				Claims = new List<Claim> {
					new Claim(JwtClaimTypes.Email, "clemas.web@gmail.com"),
					new Claim(JwtClaimTypes.Role, "admin")
				}
			}
		};
	}
}
```

```sh
GET
http://localhost:5000/.well-known/openid-configuration
```

```sh
POST
http://localhost:5000/connect/token
	Body
		x-www-form-urlencoded
			grant_type		client_credentials
			scope			api1.read
			client_id		rangelid
			client_secret	rangelsecret
```

Adicione no Program.cs

```csharp
var builder = WebApplication.CreateBuilder(args);
/*
builder.Services.AddIdentityServer()
	.AddInMemoryClients(Clients.Get())
	.AddInMemoryIdentityResources(Resources.GetIdentityResources())
	.AddInMemoryApiResources(Resources.GetApiResources())
	.AddInMemoryApiScopes(Resources.GetApiScopes())
	.AddTestUsers(Users.Get())
	.AddDeveloperSigningCredential();
*/
builder.Services
	.AddIdentityServer(options => options.KeyManagement.Enabled = true)
    .AddInMemoryClients(Clients.Get())
    .AddInMemoryIdentityResources(Resources.GetIdentityResources())
    .AddInMemoryApiResources(Resources.GetApiResources())
    .AddInMemoryApiScopes(Resources.GetApiScopes())
    .AddTestUsers(Users.Get());

var app = builder.Build();
app.UseRouting();
app.UseIdentityServer();
```

## MyApi

```sh
cd ..
dotnet new webapi --no-https -f net6.0 -n myapi
dotnet sln add myapi
cd myapi
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer --version 6.0.25
```

Powershell

```powershell
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/IdentityServer/IdentityServer4.Quickstart.UI/main/getmain.ps1'))
```

# App

```sh
cd ..
dotnet new mvc --no-https -f net6.0 -n app
dotnet sln add app
cd app
dotnet add package Microsoft.AspNetCore.Authentication.OpenIdConnect --version 6.0.25
```

# ???

```sh
dotnet new -i identityserver4.templates
dotnet new is4inmem --force
```
