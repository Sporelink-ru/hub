using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// В проде ключ — из секретов, здесь генерируется при старте
var signingKey = Key.Create(
    SignatureAlgorithm.Ed25519,
    new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
var publicKeyB64 = Convert.ToBase64String(
    signingKey.PublicKey.Export(KeyBlobFormat.RawPublicKey));

var serverId = "hub-0001";
var baseUrl = "http://localhost:5000";

app.MapGet("/.well-known/mc-federation", () => new {
    protocol_version = "0.1",
    server_id = serverId,
    server_name = "Sporelink Hub",
    auth_homeserver = baseUrl,
    public_keys = new { server_signing_key = "ed25519:" + publicKeyB64 },
    capabilities = new[] { "discovery", "manifest" }
});

app.MapGet("/federation/manifest", () => {
    var body = new JObject {
        ["manifest_version"] = "0.1",
        ["federation_id"] = "sporelink",
        ["issued_at"] = DateTime.UtcNow.ToString("O"),
        ["members"] = new JArray {
            new JObject {
                ["server_id"] = serverId,
                ["endpoint"] = baseUrl,
                ["public_key"] = "ed25519:" + publicKeyB64
            }
        },
        ["rules"] = new JObject {
            ["min_reputation_to_join"] = 0,
            ["season_duration_days"] = 45
        }
    };
    var canonical = Canonicalize(body);  // JCS
    var signingInput = "SPORELINK-MANIFEST-V1\n" + canonical;
    var sig = SignatureAlgorithm.Ed25519.Sign(
        signingKey, Encoding.UTF8.GetBytes(signingInput));

    body["signatures"] = new JArray {
        new JObject { ["signer"] = serverId,
                      ["sig"] = Convert.ToBase64String(sig) }
    };
    return Results.Text(body.ToString(Formatting.None), "application/json");
});

app.Run();

// Упрощённый JCS: сортировка ключей рекурсивно, без пробелов.
// Для продакшена используйте полноценную реализацию RFC 8785.
static string Canonicalize(JToken token) =>
    token switch {
        JObject obj => "{" + string.Join(",",
            obj.Properties().OrderBy(p => p.Name, StringComparer.Ordinal)
               .Select(p => JsonConvert.ToString(p.Name) + ":" + Canonicalize(p.Value)))
            + "}",
        JArray arr => "[" + string.Join(",", arr.Select(Canonicalize)) + "]",
        _ => token.ToString(Formatting.None)
    };