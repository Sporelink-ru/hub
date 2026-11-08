namespace Sporelink.Hub.Models;

public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string Uuid { get; set; } = string.Empty;
    public int Reputation { get; set; } = 0;
    public string Roles { get; set; } = "player";
    
    public string? SkinHash { get; set; }
    public string? SkinModel { get; set; }
    public string? CapeHash { get; set; }
}