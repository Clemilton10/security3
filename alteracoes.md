# Identity Server

[Home](./README.md) | [Alterações](./alteracoes.md) | [Instalações](./instalacoes.md) | [Artigo](./artigo.md)

# Conexao com meu banco de dados

Startup.cs

```csharp
const string connectionString = @"Data Source=DELL\MSSQLSERVER01;database=teste;trusted_connection=yes;";
```

# Senha para teste

Config.cs

```csharp
// Usuário
Username = "scott",
```

Startup.cs

```csharp
// Senha
userManager.CreateAsync(identityUser, "Password123!").Wait();
```
