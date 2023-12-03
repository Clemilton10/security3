class Program
{
	static async Task Main()
	{
		string apiUrl = "https://localhost:5000/";
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
