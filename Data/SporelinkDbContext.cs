using Microsoft.EntityFrameworkCore;
using Sporelink.Hub.Models;

namespace Sporelink.Hub.Data;

public class SporelinkDbContext : DbContext
{
    public DbSet<User> Users { get; set; }

    public DbSet<AuctionItem> Auctions { get; set; }

    public SporelinkDbContext(DbContextOptions<SporelinkDbContext> options) : base(options) { }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>()
            .HasIndex(u => u.Username)
            .IsUnique();
        modelBuilder.Entity<User>()
            .HasIndex(u => u.Uuid)
            .IsUnique();
    }
}