namespace Sporelink.Hub.Models;

public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string Uuid { get; set; } = string.Empty;
    public int Reputation { get; set; } = 0;
    public string Roles { get; set; } = "player"; // Храним как строку через запятую: "player,creator"
    
    // Данные о текстурах
    public string? SkinHash { get; set; }
    public string? SkinModel { get; set; } // "slim" или "classic"
    public string? CapeHash { get; set; }
}