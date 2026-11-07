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