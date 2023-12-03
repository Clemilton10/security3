class Program
{
	static async Task Main()
	{
		string tokenEndpoint = "https://localhost:5000/connect/token";
		string clientId = "oauthClient";
		string clientSecret = "SuperSecretPassword";
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
