using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using NSec.Cryptography;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Sporelink.Hub.Data;
using Sporelink.Hub.Models;
using Stj = System.Text.Json;

namespace Sporelink.Hub;

public class Program
{
    // ─── State ───────────────────────────────────────────────────────────
    private static string _serverId = "";
    private static string _baseUrl = "";
    private static string _dataDir = "";
    
    private static Key _signingKey = null!;
    private static string _publicKeyB64 = "";
    private static RSA _rsaKey = null!;
    
    private static ConcurrentDictionary<string, string> _joinedSessions = new();
    private static Dictionary<string, JObject> _peerCache = new();
    private static readonly object CacheLock = new();

    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        
        _dataDir = Path.Combine(AppContext.BaseDirectory, "data");
        Directory.CreateDirectory(_dataDir);

        var connString = Environment.GetEnvironmentVariable("DB_CONNECTION_STRING") 
            ?? "Host=localhost;Database=sporelink_db;Username=sporelink;Password=sporelink_secret";

        builder.Services.AddDbContext<SporelinkDbContext>(options =>
            options.UseNpgsql(connString));

        var app = builder.Build();

        // Инициализация БД
        using (var scope = app.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SporelinkDbContext>();
            db.Database.EnsureCreated();
            SeedDatabase(db);
        }

        InitializeConfig();
        InitializeKeys();
        StartPeerGossip();

        MapDiscoveryEndpoints(app);
        MapAuthEndpoints(app);
        MapReputationEndpoints(app);
        MapSessionEndpoints(app);
        MapTextureEndpoints(app);
        MapAdminEndpoints(app);
        MapNewsEndpoints(app);
        MapAuctionEndpoints(app);

        app.Run();
    }

    // ─── Initialization ──────────────────────────────────────────────────
    private static void InitializeConfig()
    {
        _serverId = Environment.GetEnvironmentVariable("SPORELINK_SERVER_ID") ?? "hub-0001";
        _baseUrl  = Environment.GetEnvironmentVariable("SPORELINK_BASE_URL") ?? "http://localhost:5000";
    }

    private static void InitializeKeys()
    {
        // Ed25519 (для JWT и подписи манифестов)
        var edKeyPath = Path.Combine(_dataDir, "ed25519.key");
        if (!File.Exists(edKeyPath))
        {
            var k = Key.Create(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            File.WriteAllBytes(edKeyPath, k.Export(KeyBlobFormat.RawPrivateKey));
            _signingKey = k;
        }
        else
        {
            _signingKey = Key.Import(SignatureAlgorithm.Ed25519, File.ReadAllBytes(edKeyPath), KeyBlobFormat.RawPrivateKey);
        }
        _publicKeyB64 = Convert.ToBase64String(_signingKey.PublicKey.Export(KeyBlobFormat.RawPublicKey));

        // RSA (для подписи скинов в Minecraft)
        var rsaKeyPath = Path.Combine(_dataDir, "rsa.key");
        _rsaKey = RSA.Create();
        if (File.Exists(rsaKeyPath))
            _rsaKey.ImportRSAPrivateKey(File.ReadAllBytes(rsaKeyPath), out _);
        else
            File.WriteAllBytes(rsaKeyPath, _rsaKey.ExportRSAPrivateKey());
    }

    private static void SeedDatabase(SporelinkDbContext db)
    {
        if (db.Users.Any()) return;

        db.Users.Add(new User
        {
            Username = "alice",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("password"),
            Uuid = "8f3a000000000000000000000000c2e1",
            Reputation = 42,
            Roles = "player,creator"
        });
        db.Users.Add(new User
        {
            Username = "bob",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("password"),
            Uuid = "a1b2000000000000000000000000c3d2",
            Reputation = 0,
            Roles = "player"
        });
        db.Users.Add(new User
        {
            Username = "ceo",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("ceo"),
            Uuid = "00000000000000000000000000000000",
            Reputation = 100,
            Roles = "player,ceo"
        });
        db.SaveChanges();
    }

    private static void StartPeerGossip()
    {
        var peersRaw = Environment.GetEnvironmentVariable("SPORELINK_PEERS") ?? "";
        var peers = peersRaw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (peers.Length == 0) return;
        
        var httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
        _ = Task.Run(async () => {
            while (true) {
                bool allOk = true;
                foreach (var peer in peers) {
                    var mf = await FetchPeerManifestAsync(httpClient, peer);
                    if (mf != null) lock (CacheLock) { _peerCache[peer] = mf; }
                    else allOk = false;
                }
                await Task.Delay(allOk ? TimeSpan.FromSeconds(15) : TimeSpan.FromSeconds(2));
            }
        });
    }

    // ─── Endpoints: Discovery & Federation ───────────────────────────────
    private static void MapDiscoveryEndpoints(WebApplication app)
    {
        app.MapGet("/", () =>
        {
            var pubKeyBytes = _rsaKey.ExportSubjectPublicKeyInfo();
            var pubKeyPem = "-----BEGIN PUBLIC KEY-----\n" +
                            Convert.ToBase64String(pubKeyBytes, Base64FormattingOptions.InsertLineBreaks) +
                            "\n-----END PUBLIC KEY-----";
            return Results.Json(new
            {
                meta = new { serverName = "Sporelink Hub", implementationName = "Sporelink", implementationVersion = "0.1.0" },
                signaturePublickey = pubKeyPem,
                skinDomains = new[] { "localhost", "127.0.0.1", "sporelink.ru" }
            });
        });

        app.MapGet("/.well-known/mc-federation", () => new
        {
            protocol_version = "0.1",
            server_id = _serverId,
            server_name = "Sporelink Hub",
            auth_homeserver = _baseUrl,
            public_keys = new
            {
                server_signing_key = "ed25519:" + _publicKeyB64,
                auth_signing_key   = "ed25519:" + _publicKeyB64
            },
            capabilities = new[] { "discovery", "manifest", "auth" }
        });

        app.MapGet("/federation/manifest", () =>
        {
            var membersById = new Dictionary<string, JObject>
            {
                [_serverId] = new JObject
                {
                    ["server_id"] = _serverId,
                    ["endpoint"] = _baseUrl,
                    ["public_key"] = "ed25519:" + _publicKeyB64
                }
            };

            lock (CacheLock)
            {
                foreach (var peerMf in _peerCache.Values)
                {
                    if (peerMf["members"] is not JArray arr) continue;
                    foreach (var m in arr)
                    {
                        var id = m!["server_id"]?.ToString();
                        if (string.IsNullOrEmpty(id)) continue;
                        if (!membersById.ContainsKey(id))
                            membersById[id] = (JObject)m.DeepClone();
                    }
                }
            }

            var body = new JObject
            {
                ["manifest_version"] = "0.1",
                ["federation_id"] = "sporelink",
                ["issued_at"] = DateTime.UtcNow.ToString("O"),
                ["members"] = new JArray(membersById.Values.ToArray()),
                ["rules"] = new JObject
                {
                    ["min_reputation_to_join"] = 0,
                    ["season_duration_days"] = 45
                }
            };

            var canonical    = Canonicalize(body);
            var signingInput = "SPORELINK-MANIFEST-V1\n" + canonical;
            var sig = SignatureAlgorithm.Ed25519.Sign(_signingKey, Encoding.UTF8.GetBytes(signingInput));

            body["signatures"] = new JArray
            {
                new JObject { ["signer"] = _serverId, ["sig"] = Convert.ToBase64String(sig) }
            };

            return Results.Text(body.ToString(Formatting.None), "application/json");
        });
    }

    // ─── Endpoints: Auth & Reputation ────────────────────────────────────
    private static void MapAuthEndpoints(WebApplication app)
    {
        app.MapPost("/authserver/register", (RegisterRequest req, SporelinkDbContext db) =>
        {
            if (db.Users.Any(u => u.Username == req.Username))
                return Results.BadRequest(new { error = "Username already taken" });
                
            if (db.Users.Any(u => u.Email == req.Email))
                return Results.BadRequest(new { error = "Email already registered" });

            var user = new User {
                Username = req.Username,
                Email = req.Email, // <--- Сохраняем Email
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(req.Password),
                Uuid = Guid.NewGuid().ToString("N"),
                Reputation = 0,
                Roles = "player"
            };
            db.Users.Add(user);
            db.SaveChanges();
            return Results.Ok(new { message = "Registered successfully", uuid = user.Uuid });
        });

        app.MapPost("/authserver/authenticate", (LoginRequest req, SporelinkDbContext db) =>
        {
            var user = db.Users.FirstOrDefault(u => u.Username == req.Username);
            if (user == null || !BCrypt.Net.BCrypt.Verify(req.Password, user.PasswordHash))
                return Results.Json(new { error = "ForbiddenOperationException", errorMessage = "Invalid credentials" }, statusCode: 403);

            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var header  = new { alg = "EdDSA", typ = "JWT", kid = _serverId };
            var payload = new {
                iss = _serverId, sub = user.Uuid, name = user.Username,
                iat = now, exp = now + 86400, aud = "sporelink",
                reputation = user.Reputation, roles = user.Roles.Split(','), federation = "sporelink" 
            };

            var headerB64 = Base64UrlEncode(Stj.JsonSerializer.SerializeToUtf8Bytes(header));
            var payloadB64 = Base64UrlEncode(Stj.JsonSerializer.SerializeToUtf8Bytes(payload));
            var signingInput = headerB64 + "." + payloadB64;
            var sig = SignatureAlgorithm.Ed25519.Sign(_signingKey, Encoding.UTF8.GetBytes(signingInput));
            var jwt = signingInput + "." + Base64UrlEncode(sig);

            return Results.Json(new {
                accessToken = jwt,
                clientToken = req.ClientToken ?? Guid.NewGuid().ToString("N"),
                availableProfiles = new[] { new { id = user.Uuid, name = user.Username } },
                selectedProfile = new { id = user.Uuid, name = user.Username }
            });
        });
    }

    private static void MapReputationEndpoints(WebApplication app)
    {
        app.MapGet("/reputation/{playerId}", (string playerId, SporelinkDbContext db) =>
        {
            var user = db.Users.FirstOrDefault(u => u.Uuid == playerId);
            if (user == null) return Results.NotFound(new { error = "player not found" });
            
            return Results.Json(new { player_id = playerId, name = user.Username, reputation = user.Reputation, roles = user.Roles.Split(',') });
        });

        app.MapPost("/reputation/{playerId}", (string playerId, ReputationUpdate req, SporelinkDbContext db) =>
        {
            var user = db.Users.FirstOrDefault(u => u.Uuid == playerId);
            if (user == null) return Results.NotFound(new { error = "player not found" });

            int newRep = user.Reputation;
            if (req.Delta.HasValue) newRep += req.Delta.Value;
            if (req.Set.HasValue)   newRep = req.Set.Value;
            user.Reputation = Math.Clamp(newRep, -100, 100);
            
            db.SaveChanges();
            return Results.Json(new { player_id = playerId, reputation = user.Reputation, roles = user.Roles.Split(',') });
        });

        app.MapGet("/players", (SporelinkDbContext db) => Results.Json(db.Users.Select(u => new
        {
            player_id = u.Uuid, name = u.Username, reputation = u.Reputation, roles = u.Roles.Split(',')
        }).ToList()));
    }

    // ─── Endpoints: Session & Minecraft ──────────────────────────────────
    private static void MapSessionEndpoints(WebApplication app)
    {
        app.MapPost("/sessionserver/session/minecraft/join", (JoinRequest req, SporelinkDbContext db) =>
        {
            var user = db.Users.FirstOrDefault(u => u.Uuid == req.SelectedProfile);
            if (user == null)
            {
                Console.WriteLine($"[session] Join failed: unknown UUID {req.SelectedProfile}");
                return Results.Json(new { error = "ForbiddenOperationException", errorMessage = "Invalid token" }, statusCode: 403);
            }
            
            _joinedSessions[req.ServerId] = user.Username;
            Console.WriteLine($"[session] Join: {user.Username} -> {req.ServerId}");
            return Results.NoContent();
        });

        app.MapGet("/sessionserver/session/minecraft/hasJoined", (string username, string serverId, SporelinkDbContext db) =>
        {
            if (_joinedSessions.TryGetValue(serverId, out var joinedUser) && joinedUser == username)
            {
                var user = db.Users.FirstOrDefault(u => u.Username == username);
                if (user != null)
                {
                    _joinedSessions.TryRemove(serverId, out _);
                    return Results.Json(new { id = user.Uuid, name = user.Username, properties = new object[] { } });
                }
            }
            return Results.NotFound();
        });

        app.MapGet("/sessionserver/session/minecraft/profile/{uuid}", (string uuid, SporelinkDbContext db, bool unsigned = false) =>
        {
            string cleanUuid = uuid.Replace("-", "");
            var user = db.Users.FirstOrDefault(u => u.Uuid == cleanUuid);
            if (user == null) return Results.NotFound();

            var textures = new Dictionary<string, object>();
            if (!string.IsNullOrEmpty(user.SkinHash))
                textures["SKIN"] = new { url = $"{_baseUrl}/textures/{user.SkinHash}", metadata = new { model = user.SkinModel ?? "classic" } };
            if (!string.IsNullOrEmpty(user.CapeHash))
                textures["CAPE"] = new { url = $"{_baseUrl}/textures/{user.CapeHash}" };

            string? texturesValue = null;
            string? texturesSignature = null;

            if (textures.Count > 0)
            {
                var payload = new { timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), profileId = cleanUuid, profileName = user.Username, textures = textures };
                string json = JsonConvert.SerializeObject(payload, Formatting.None);
                texturesValue = Convert.ToBase64String(Encoding.UTF8.GetBytes(json));

                if (!unsigned)
                    texturesSignature = Convert.ToBase64String(_rsaKey.SignData(Encoding.UTF8.GetBytes(texturesValue), HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1));
            }

            var props = new List<object>();
            if (texturesValue != null) {
                var prop = new Dictionary<string, object> { ["name"] = "textures", ["value"] = texturesValue };
                if (texturesSignature != null) prop["signature"] = texturesSignature;
                props.Add(prop);
            }

            return Results.Json(new { id = cleanUuid, name = user.Username, properties = props });
        });
    }

    // ─── Endpoints: Textures ─────────────────────────────────────────────
    private static void MapTextureEndpoints(WebApplication app)
    {
        app.MapPut("/api/user/profile/{uuid}/{textureType}", async (string uuid, string textureType, HttpRequest req, SporelinkDbContext db) =>
        {
            string? authUuid = GetUuidFromAuth(req);
            if (authUuid == null || authUuid != uuid) return Results.Unauthorized();

            var form = await req.ReadFormAsync();
            var file = form.Files.GetFile("file");
            if (file == null || file.Length == 0) return Results.BadRequest(new { error = "No file provided" });

            using var ms = new MemoryStream();
            await file.CopyToAsync(ms);
            var bytes = ms.ToArray();
            string hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            string filePath = Path.Combine(_dataDir, $"{hash}.png");
            
            await File.WriteAllBytesAsync(filePath, bytes);

            var user = db.Users.FirstOrDefault(u => u.Uuid == uuid);
            if (user != null)
            {
                if (textureType == "skin") {
                    user.SkinHash = hash;
                    user.SkinModel = form["model"].ToString() == "slim" ? "slim" : "classic";
                } else if (textureType == "cape") {
                    user.CapeHash = hash;
                }
                db.SaveChanges();
            }

            return Results.NoContent();
        });

        app.MapDelete("/api/user/profile/{uuid}/{textureType}", (string uuid, string textureType, HttpRequest req, SporelinkDbContext db) =>
        {
            string? authUuid = GetUuidFromAuth(req);
            if (authUuid == null || authUuid != uuid) return Results.Unauthorized();

            var user = db.Users.FirstOrDefault(u => u.Uuid == uuid);
            if (user != null)
            {
                if (textureType == "skin") user.SkinHash = null;
                else if (textureType == "cape") user.CapeHash = null;
                db.SaveChanges();
            }
            return Results.NoContent();
        });

        app.MapGet("/textures/{hash}", (string hash) =>
        {
            string filePath = Path.Combine(_dataDir, $"{hash}.png");
            if (!File.Exists(filePath)) return Results.NotFound();
            return Results.File(filePath, "image/png");
        });
    }

    // ─── Endpoints: Admin ────────────────────────────────────────────────
    private static void MapAdminEndpoints(WebApplication app)
    {
        // Получить список всех игроков
        app.MapGet("/admin/users", (HttpRequest req, SporelinkDbContext db) =>
        {
            if (!HasRole(req, "admin", db)) return Results.Unauthorized();

            return Results.Json(db.Users.Select(u => new
            {
                uuid = u.Uuid,
                username = u.Username,
                email = u.Email,
                reputation = u.Reputation,
                roles = u.Roles.Split(',')
            }).ToList());
        });

        // Изменить роль игрока
        app.MapPost("/admin/users/{uuid}/role", (string uuid, RoleUpdate body, HttpRequest req, SporelinkDbContext db) =>
        {
            if (!HasRole(req, "admin", db)) return Results.Unauthorized();

            var targetUser = db.Users.FirstOrDefault(u => u.Uuid == uuid);
            if (targetUser == null) return Results.NotFound(new { error = "User not found" });

            // Защита: нельзя понизить/повысить CEO'в, если ты не CEO
            bool isCeo = HasRole(req, "ceo", db);
            if ((targetUser.Roles.Contains("ceo") || body.Role == "ceo") && !isCeo)
                return Results.Json(new { error = "Only CEO can manage CEO roles" }, statusCode: 403);

            // Формируем новую строку ролей
            if (body.Role == "player")
                targetUser.Roles = "player"; // Сбрасываем всё до игрока
            else if (!targetUser.Roles.Contains(body.Role))
                targetUser.Roles = targetUser.Roles + "," + body.Role; // Добавляем роль

            db.SaveChanges();
            return Results.Ok(new { message = "Role updated", roles = targetUser.Roles.Split(',') });
        });
    }

    // Хелпер для проверки ролей
    private static bool HasRole(HttpRequest req, string requiredRole, SporelinkDbContext db)
    {
        var uuid = GetUuidFromAuth(req);
        if (uuid == null) return false;

        var user = db.Users.FirstOrDefault(u => u.Uuid == uuid);
        if (user == null) return false;

        var roles = user.Roles.Split(',').Select(r => r.Trim()).ToList();
        
        if (roles.Contains("ceo")) return true; // CEO может всё
        if (requiredRole == "admin" && roles.Contains("admin")) return true;
        if (requiredRole == "moderator" && (roles.Contains("moderator") || roles.Contains("admin"))) return true;
        
        return false;
    }

    // ─── Background Helpers ──────────────────────────────────────────────
    private static async Task<JObject?> FetchPeerManifestAsync(HttpClient client, string peerUrl)
    {
        try
        {
            var wkBody = await client.GetStringAsync(peerUrl.TrimEnd('/') + "/.well-known/mc-federation");
            var wk = JObject.Parse(wkBody);
            var peerPubKeyB64 = wk["public_keys"]!["server_signing_key"]!.ToString().Replace("ed25519:", "");

            var mfBody = await client.GetStringAsync(peerUrl.TrimEnd('/') + "/federation/manifest");
            var mf = JObject.Parse(mfBody);

            var signatures = mf["signatures"] as JArray;
            if (signatures == null || signatures.Count == 0) return null;
            var sigB64 = signatures[0]!["sig"]!.ToString();

            var toSign = (JObject)mf.DeepClone();
            toSign.Remove("signatures");
            var canonical    = Canonicalize(toSign);
            var signingInput = "SPORELINK-MANIFEST-V1\n" + canonical;

            var peerPub = PublicKey.Import(SignatureAlgorithm.Ed25519, Convert.FromBase64String(peerPubKeyB64), KeyBlobFormat.RawPublicKey);
            var ok = SignatureAlgorithm.Ed25519.Verify(peerPub, Encoding.UTF8.GetBytes(signingInput), Convert.FromBase64String(sigB64));
            
            return ok ? mf : null;
        }
        catch { return null; }
    }

    // ─── News API ────────────────────────────────────────────────────────
    private static void MapNewsEndpoints(WebApplication app)
    {
        app.MapGet("/api/news", () =>
        {
            // В реальном проекте вы можете читать это из файла или БД
            var news = new[]
            {
                new { 
                    id = 1, 
                    title = "Добро пожаловать в Sporelink!", 
                    content = "Мы рады приветствовать вас в нашей новой федеративной сети. Присоединяйтесь к серверам, зарабатывайте монеты и общайтесь!", 
                    date = "2026-11-12" 
                },
                new { 
                    id = 2, 
                    title = "Обновление: Магазин и Плащи", 
                    content = "Теперь вы можете покупать предметы за внутриигровую валюту в /shop и загружать свои плащи прямо в лаунчере!", 
                    date = "2026-11-12" 
                }
            };
            
            return Results.Json(news);
        });
    }

    // ─── Auction API ─────────────────────────────────────────────────────
    private static void MapAuctionEndpoints(WebApplication app)
    {
        // Получить все активные лоты
        app.MapGet("/api/auction", (SporelinkDbContext db) =>
        {
            var lots = db.Auctions.Where(a => !a.IsSold)
                .OrderByDescending(a => a.Id)
                .Select(a => new { 
                    a.Id, 
                    a.SellerUuid,
                    a.SellerName, 
                    a.ItemBase64, 
                    a.Price 
                })
                .ToList();
            return Results.Json(lots);
        });

        // Выставить предмет на аукцион
        app.MapPost("/api/auction", (AuctionCreate req, SporelinkDbContext db) =>
        {
            var user = db.Users.FirstOrDefault(u => u.Uuid == req.SellerUuid);
            if (user == null) return Results.Unauthorized();

            var lot = new AuctionItem
            {
                SellerUuid = req.SellerUuid,
                SellerName = user.Username,
                ItemBase64 = req.ItemBase64,
                Price = req.Price
            };
            db.Auctions.Add(lot);
            db.SaveChanges();
            return Results.Ok(new { message = "Item listed", lotId = lot.Id });
        });

        // Купить предмет
        app.MapPost("/api/auction/{id}/buy", (int id, BuyRequest req, SporelinkDbContext db) =>
        {
            var lot = db.Auctions.FirstOrDefault(a => a.Id == id && !a.IsSold);
            if (lot == null) return Results.BadRequest(new { error = "Lot not found or already sold" });

            // Защита: нельзя купить свой же предмет
            if (lot.SellerUuid == req.BuyerUuid) return Results.BadRequest(new { error = "You cannot buy your own item" });

            lot.IsSold = true;
            lot.BuyerUuid = req.BuyerUuid;
            db.SaveChanges();

            // TODO: Здесь мы должны вызвать Node, чтобы перевести деньги от покупателя к продавцу.
            // Но для простоты MVP мы сделаем это на стороне плагина, который вызовет /transfer.

            return Results.Ok(new { message = "Item bought", itemBase64 = lot.ItemBase64 });
        });
    }

    // ─── Crypto & Auth Helpers ───────────────────────────────────────────
    private static string? GetUuidFromAuth(HttpRequest req)
    {
        string? authHeader = req.Headers["Authorization"];
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ")) return null;
        
        string jwt = authHeader.Substring(7);
        try
        {
            string[] parts = jwt.Split('.');
            if (parts.Length != 3) return null;
            
            byte[] sig = Base64UrlDecode(parts[2]);
            string signingInput = parts[0] + "." + parts[1];
            var pub = PublicKey.Import(SignatureAlgorithm.Ed25519, Convert.FromBase64String(_publicKeyB64), KeyBlobFormat.RawPublicKey);
            if (!SignatureAlgorithm.Ed25519.Verify(pub, Encoding.UTF8.GetBytes(signingInput), sig)) return null;

            string payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[1]));
            var payload = JObject.Parse(payloadJson);
            return payload["sub"]?.ToString();
        }
        catch { return null; }
    }

    private static string Canonicalize(JToken token) =>
        token switch
        {
            JObject obj =>
                "{" + string.Join(",", obj.Properties()
                    .OrderBy(p => p.Name, StringComparer.Ordinal)
                    .Select(p => JsonConvert.ToString(p.Name) + ":" + Canonicalize(p.Value)))
                + "}",
            JArray arr => "[" + string.Join(",", arr.Select(Canonicalize)) + "]",
            _ => token.ToString(Formatting.None)
        };

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string input)
    {
        string padded = input.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        return Convert.FromBase64String(padded);
    }
}

// ─── DTOs ────────────────────────────────────────────────────────────────
internal record LoginRequest(string Username, string Password, string? ClientToken);
internal record RegisterRequest(string Username, string Password, string Email);
internal record ReputationUpdate(int? Delta, int? Set);
internal record JoinRequest(string AccessToken, string SelectedProfile, string ServerId);
internal record RoleUpdate(string Role);
internal record AuctionCreate(string SellerUuid, string ItemBase64, long Price);
internal record BuyRequest(string BuyerUuid);