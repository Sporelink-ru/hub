namespace Sporelink.Hub.Models;

public class AuctionItem
{
    public int Id { get; set; }
    public string SellerUuid { get; set; } = string.Empty;
    public string SellerName { get; set; } = string.Empty;
    public string ItemBase64 { get; set; } = string.Empty; 
    public long Price { get; set; }
    public bool IsSold { get; set; } = false;
    public string? BuyerUuid { get; set; }
}