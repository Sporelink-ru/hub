using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Stj = System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// ─── Keys ────────────────────────────────────────────────────────────
// Ed25519 key. In prod: load from secrets, never generate on start.
var signingKey = Key.Create(
    SignatureAlgorithm.Ed25519,
    new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
var publicKeyB64 = Convert.ToBase64String(
    signingKey.PublicKey.Export(KeyBlobFormat.RawPublicKey));

var serverId = "hub-0001";
var baseUrl = "http://localhost:5000";

// MVP: same key signs manifests and JWTs. Split into authKey in v0.3.
var authKey = signingKey;

// ─── In-memory user store ────────────────────────────────────────────
// MVP ONLY. Replace SHA256 with BCrypt before any public launch.
var users = new Dictionary<string, (string PasswordHash, string Uuid, string Name)>
{
    ["alice"] = (
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("password"))),
        "8f3a000000000000000000000000c2e1",
        "Alice"
    )
};

// ─── Discovery ───────────────────────────────────────────────────────
app.MapGet("/.well-known/mc-federation", () => new
{
    protocol_version = "0.1",
    server_id = serverId,
    server_name = "Sporelink Hub",
    auth_homeserver = baseUrl,
    public_keys = new
    {
        server_signing_key = "ed25519:" + publicKeyB64,
        auth_signing_key   = "ed25519:" + publicKeyB64
    },
    capabilities = new[] { "discovery", "manifest", "auth" }
});

// ─── Signed manifest ─────────────────────────────────────────────────
app.MapGet("/federation/manifest", () =>
{
    var body = new JObject
    {
        ["manifest_version"] = "0.1",
        ["federation_id"] = "sporelink",
        ["issued_at"] = DateTime.UtcNow.ToString("O"),
        ["members"] = new JArray
        {
            new JObject
            {
                ["server_id"] = serverId,
                ["endpoint"] = baseUrl,
                ["public_key"] = "ed25519:" + publicKeyB64
            }
        },
        ["rules"] = new JObject
        {
            ["min_reputation_to_join"] = 0,
            ["season_duration_days"] = 45
        }
    };

    var canonical = Canonicalize(body);
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
    {
        return Results.Json(
            new
            {
                error = "ForbiddenOperationException",
                errorMessage = "Invalid credentials"
            },
            statusCode: 403);
    }

    var hash = Convert.ToHexString(
        SHA256.HashData(Encoding.UTF8.GetBytes(req.Password)));
    if (hash != user.PasswordHash)
    {
        return Results.Json(
            new
            {
                error = "ForbiddenOperationException",
                errorMessage = "Invalid credentials"
            },
            statusCode: 403);
    }

    var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    var header = new { alg = "EdDSA", typ = "JWT", kid = serverId };
    var payload = new
    {
        iss = serverId,
        sub = user.Uuid,
        name = user.Name,
        iat = now,
        exp = now + 86400,
        aud = "sporelink"
    };

    var headerB64    = Base64UrlEncode(Stj.JsonSerializer.SerializeToUtf8Bytes(header));
    var payloadB64   = Base64UrlEncode(Stj.JsonSerializer.SerializeToUtf8Bytes(payload));
    var signingInput = headerB64 + "." + payloadB64;

    var sig = SignatureAlgorithm.Ed25519.Sign(
        authKey, Encoding.UTF8.GetBytes(signingInput));
    var jwt = signingInput + "." + Base64UrlEncode(sig);

    return Results.Json(new
    {
        accessToken       = jwt,
        clientToken       = req.ClientToken ?? Guid.NewGuid().ToString("N"),
        availableProfiles = new[]
        {
            new { id = user.Uuid, name = user.Name }
        },
        selectedProfile   = new { id = user.Uuid, name = user.Name }
    });
});

app.Run();

// ─── Helpers ─────────────────────────────────────────────────────────

// Simplified JCS: recursive key sorting, no whitespace.
// For v0.2, swap for a proper RFC 8785 library on both sides.
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

// ─── DTOs ────────────────────────────────────────────────────────────
internal record LoginRequest(string Username, string Password, string? ClientToken);