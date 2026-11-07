using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Stj = System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// ─── Config from env ─────────────────────────────────────────────────
var serverId   = Environment.GetEnvironmentVariable("SPORELINK_SERVER_ID")   ?? "hub-0001";
var serverName = Environment.GetEnvironmentVariable("SPORELINK_SERVER_NAME") ?? "Sporelink Hub";
var baseUrl    = Environment.GetEnvironmentVariable("SPORELINK_BASE_URL")    ?? "http://localhost:5000";
var peersRaw   = Environment.GetEnvironmentVariable("SPORELINK_PEERS")       ?? "";
var peers = peersRaw
    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

// ─── Keys ────────────────────────────────────────────────────────────
var signingKey = Key.Create(
    SignatureAlgorithm.Ed25519,
    new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
var publicKeyB64 = Convert.ToBase64String(
    signingKey.PublicKey.Export(KeyBlobFormat.RawPublicKey));
var authKey = signingKey;

// ─── Users with reputation and roles ─────────────────────────────────
var users = new Dictionary<string, UserRecord>
{
    ["alice"] = new UserRecord(
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("password"))),
        "8f3a000000000000000000000000c2e1",
        "Alice",
        42,
        new[] { "player", "creator" }
    )
};
// Хранилище активных сессий: serverId -> username
var joinedSessions = new System.Collections.Concurrent.ConcurrentDictionary<string, string>();
if (serverId == "hub-0002")
{
    users["bob"] = new UserRecord(
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("password"))),
        "a1b2000000000000000000000000c3d2",
        "Bob",
        -5,
        new[] { "player" }
    );
}

// ─── Peer manifest cache ─────────────────────────────────────────────
var httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
var peerCache = new Dictionary<string, JObject>();
var cacheLock = new object();

async Task<JObject?> FetchPeerManifestAsync(string peerUrl)
{
    try
    {
        // 1. Peer's well-known
        var wkBody = await httpClient.GetStringAsync(
            peerUrl.TrimEnd('/') + "/.well-known/mc-federation");
        var wk = JObject.Parse(wkBody);
        var peerPubKeyB64 = wk["public_keys"]!["server_signing_key"]!
            .ToString().Replace("ed25519:", "");

        // 2. Peer's manifest
        var mfBody = await httpClient.GetStringAsync(
            peerUrl.TrimEnd('/') + "/federation/manifest");
        var mf = JObject.Parse(mfBody);

        // 3. Verify signature
        var signatures = mf["signatures"] as JArray;
        if (signatures == null || signatures.Count == 0) return null;
        var sigB64 = signatures[0]!["sig"]!.ToString();

        var toSign = (JObject)mf.DeepClone();
        toSign.Remove("signatures");
        var canonical    = Canonicalize(toSign);
        var signingInput = "SPORELINK-MANIFEST-V1\n" + canonical;

        var peerPub = PublicKey.Import(
            SignatureAlgorithm.Ed25519,
            Convert.FromBase64String(peerPubKeyB64),
            KeyBlobFormat.RawPublicKey);
        var ok = SignatureAlgorithm.Ed25519.Verify(
            peerPub,
            Encoding.UTF8.GetBytes(signingInput),
            Convert.FromBase64String(sigB64));
        if (!ok) return null;

        return mf;
    }
    catch
    {
        return null;
    }
}

// Background refresh: no HTTP calls from request path → no deadlock.
_ = Task.Run(async () =>
{
    while (true)
    {
        bool allOk = true;
        foreach (var peer in peers)
        {
            var mf = await FetchPeerManifestAsync(peer);
            if (mf != null)
            {
                lock (cacheLock) { peerCache[peer] = mf; }
            }
            else
            {
                allOk = false;
            }
        }
        await Task.Delay(allOk
            ? TimeSpan.FromSeconds(15)
            : TimeSpan.FromSeconds(2));
    }
});

// ─── Discovery ───────────────────────────────────────────────────────
app.MapGet("/.well-known/mc-federation", () => new
{
    protocol_version = "0.1",
    server_id = serverId,
    server_name = serverName,
    auth_homeserver = baseUrl,
    public_keys = new
    {
        server_signing_key = "ed25519:" + publicKeyB64,
        auth_signing_key   = "ed25519:" + publicKeyB64
    },
    capabilities = new[] { "discovery", "manifest", "auth" }
});

// ─── Aggregated signed manifest ──────────────────────────────────────
app.MapGet("/federation/manifest", () =>
{
    var membersById = new Dictionary<string, JObject>
    {
        [serverId] = new JObject
        {
            ["server_id"] = serverId,
            ["endpoint"] = baseUrl,
            ["public_key"] = "ed25519:" + publicKeyB64
        }
    };

    // Add members from cached peer manifests (read-only, no HTTP)
    lock (cacheLock)
    {
        foreach (var peerMf in peerCache.Values)
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
    var sig = SignatureAlgorithm.Ed25519.Sign(
        signingKey, Encoding.UTF8.GetBytes(signingInput));

    body["signatures"] = new JArray
    {
        new JObject
        {
            ["signer"] = serverId,
            ["sig"] = Convert.ToBase64String(sig)
        }
    };

    return Results.Text(body.ToString(Formatting.None), "application/json");
});

// ─── Authentication ──────────────────────────────────────────────────
app.MapPost("/authserver/authenticate", (LoginRequest req) =>
{
    if (!users.TryGetValue(req.Username, out var user))
        return Results.Json(new { error = "ForbiddenOperationException",
                                  errorMessage = "Invalid credentials" }, statusCode: 403);

    var hash = Convert.ToHexString(
        SHA256.HashData(Encoding.UTF8.GetBytes(req.Password)));
    if (hash != user.PasswordHash)
        return Results.Json(new { error = "ForbiddenOperationException",
                                  errorMessage = "Invalid credentials" }, statusCode: 403);

    var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    var header  = new { alg = "EdDSA", typ = "JWT", kid = serverId };
    var payload = new
    {
        iss = serverId,
        sub = user.Uuid,
        name = user.Name,
        iat = now,
        exp = now + 86400,
        aud = "sporelink",
        reputation = user.Reputation, 
        roles = user.Roles,        
        federation = "sporelink" 
    };

    var headerB64    = Base64UrlEncode(Stj.JsonSerializer.SerializeToUtf8Bytes(header));
    var payloadB64   = Base64UrlEncode(Stj.JsonSerializer.SerializeToUtf8Bytes(payload));
    var signingInput = headerB64 + "." + payloadB64;

    var sig = SignatureAlgorithm.Ed25519.Sign(
        authKey, Encoding.UTF8.GetBytes(signingInput));
    var jwt = signingInput + "." + Base64UrlEncode(sig);

    return Results.Json(new
    {
        accessToken = jwt,
        clientToken = req.ClientToken ?? Guid.NewGuid().ToString("N"),
        availableProfiles = new[] { new { id = user.Uuid, name = user.Name } },
        selectedProfile = new { id = user.Uuid, name = user.Name }
    });
});

// ─── Reputation: read ────────────────────────────────────────────────
app.MapGet("/reputation/{playerId}", (string playerId) =>
{
    foreach (var kv in users)
    {
        if (kv.Value.Uuid == playerId)
        {
            return Results.Json(new
            {
                player_id  = playerId,
                name       = kv.Value.Name,
                reputation = kv.Value.Reputation,
                roles      = kv.Value.Roles
            });
        }
    }
    return Results.NotFound(new { error = "player not found" });
});

// ─── Reputation: update (MVP, no auth) ───────────────────────────────
app.MapPost("/reputation/{playerId}", (string playerId, ReputationUpdate req) =>
{
    string? key = null;
    UserRecord? u = null;
    foreach (var kv in users)
    {
        if (kv.Value.Uuid == playerId) { key = kv.Key; u = kv.Value; break; }
    }
    if (key == null || u == null)
        return Results.NotFound(new { error = "player not found" });

    int newRep = u.Reputation;
    if (req.Delta.HasValue) newRep += req.Delta.Value;
    if (req.Set.HasValue)   newRep = req.Set.Value;
    newRep = Math.Clamp(newRep, -100, 100);

    users[key] = u with { Reputation = newRep };

    return Results.Json(new
    {
        player_id  = playerId,
        reputation = newRep,
        roles      = u.Roles
    });
});

// ─── Admin: list all players (MVP) ───────────────────────────────────
app.MapGet("/players", () =>
    Results.Json(users.Values.Select(u => new
    {
        player_id  = u.Uuid,
        name       = u.Name,
        reputation = u.Reputation,
        roles      = u.Roles
    })));

// ─── Authlib-injector Metadata ───────────────────────────────────────
// Генерируем RSA-ключ для подписи скинов (authlib-injector требует его наличия)
using var rsa = System.Security.Cryptography.RSA.Create(2048);
var pubKeyBytes = rsa.ExportSubjectPublicKeyInfo();
var pubKeyPem = "-----BEGIN PUBLIC KEY-----\n" + 
                Convert.ToBase64String(pubKeyBytes, Base64FormattingOptions.InsertLineBreaks) + 
                "\n-----END PUBLIC KEY-----";

app.MapGet("/", () => Results.Json(new
{
    meta = new
    {
        serverName = "Sporelink Hub",
        implementationName = "Sporelink",
        implementationVersion = "0.1.0"
    },
    signaturePublickey = pubKeyPem,
    skinDomains = new[] { "localhost", "sporelink.ru" }
}));

// ─── Session Server: join (клиент) ───────────────────────────────────
app.MapPost("/sessionserver/session/minecraft/join", (JoinRequest req) =>
{
    // req.SelectedProfile содержит UUID. Нам нужно найти ник игрока по этому UUID.
    var user = users.Values.FirstOrDefault(u => u.Uuid == req.SelectedProfile);
    
    if (user != null)
    {
        // Сохраняем НИК, чтобы сервер потом мог его проверить
        joinedSessions[req.ServerId] = user.Name;
        Console.WriteLine($"[session] Join: {user.Name} -> {req.ServerId}");
        return Results.NoContent();
    }
    
    Console.WriteLine($"[session] Join failed: unknown UUID {req.SelectedProfile}");
    return Results.Json(new { error = "ForbiddenOperationException", errorMessage = "Invalid token" }, statusCode: 403);
});

// ─── Session Server: hasJoined (сервер) ──────────────────────────────
app.MapGet("/sessionserver/session/minecraft/hasJoined", (string username, string serverId) =>
{
    if (joinedSessions.TryGetValue(serverId, out var joinedUser) && joinedUser == username)
    {
        var user = users.Values.FirstOrDefault(u => u.Name == username);
        if (user != null)
        {
            // Сессия одноразовая — удаляем её после использования
            joinedSessions.TryRemove(serverId, out _);
            
            return Results.Json(new
            {
                id = user.Uuid,
                name = user.Name,
                properties = new object[] { } // Скины добавим позже
            });
        }
    }
    return Results.NotFound();
});

// ─── Session Server: profile (скины) ─────────────────────────────────
app.MapGet("/sessionserver/session/minecraft/profile/{uuid}", (string uuid) =>
{
    // Убираем дефисы, если они есть, чтобы сравнить с нашим форматом
    string cleanUuid = uuid.Replace("-", "");
    var user = users.Values.FirstOrDefault(u => u.Uuid == cleanUuid);
    
    if (user == null)
    {
        return Results.NotFound();
    }

    return Results.Json(new
    {
        id = user.Uuid,
        name = user.Name,
        // Пока возвращаем пустой массив (без скинов). 
        // Позже сюда можно добавить Base64-строку с URL скина.
        properties = new object[] { } 
    });
});

app.Run();

// ─── Helpers ─────────────────────────────────────────────────────────
static string Canonicalize(JToken token) =>
    token switch
    {
        JObject obj =>
            "{" + string.Join(",", obj.Properties()
                .OrderBy(p => p.Name, StringComparer.Ordinal)
                .Select(p => JsonConvert.ToString(p.Name) + ":" + Canonicalize(p.Value)))
            + "}",
        JArray arr =>
            "[" + string.Join(",", arr.Select(Canonicalize)) + "]",
        _ => token.ToString(Formatting.None)
    };

static string Base64UrlEncode(byte[] bytes) =>
    Convert.ToBase64String(bytes)
        .TrimEnd('=')
        .Replace('+', '-')
        .Replace('/', '_');

internal record LoginRequest(string Username, string Password, string? ClientToken);
record UserRecord(string PasswordHash, string Uuid, string Name, int Reputation, string[] Roles);
internal record ReputationUpdate(int? Delta, int? Set);
internal record JoinRequest(string AccessToken, string SelectedProfile, string ServerId);