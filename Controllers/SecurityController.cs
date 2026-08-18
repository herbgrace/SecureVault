namespace SecureVault;

using System.Text;
using System.Text.Json;
using System.Text.Unicode;
using System.Security.Cryptography;
using System.Security.Claims;
using System.Runtime.CompilerServices;

using Google.Apis.Auth.OAuth2;
using Google.Apis.Oauth2.v2;
using Google.Apis.Services;

using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using Google.Apis.Oauth2.v2.Data;

public static class SecurityController
{
    private static string? savedToken;

    private static SymmetricSecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("VAULT_JWT_SECRET") ?? ""));
    private static JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
    private static readonly string Issuer = "Secure Vault";
    private static readonly string Audience = "Secure Vault Users";
    public static bool IsCorrectPassword(string username, string password)
    {
        var existing = FileController.LoadUsers();
        User? currentUser = existing.GetValueOrDefault(username);

        // User doesn't exist in the system (bad username)
        if (currentUser == null)
        {
            return false;
        }

        // The password doesn't match
        if (!CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(currentUser.hash),
            Encoding.UTF8.GetBytes(SaltedHash(currentUser.salt, password))
        ))
        {
            return false;
        }
        return true;
    }
    public static bool PasswordFollowsConstraints(string password)
    {
        return !(password.Length < 8 || !password.Any(char.IsDigit) || !password.Any(char.IsUpper));
    }

    public static string SaltedHash(string salt, string input)
    {
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(salt + input))).ToLower();
    }   

    public static byte[] DeriveKey(string password, byte[] salt)
    {
        return Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, 100_000, HashAlgorithmName.SHA256, 32);
    }

    public static (byte[] ciphertext, byte[] iv) AesEncrypt(byte[] data, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.GenerateIV();
        using var ms = new MemoryStream();
        using var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
        cs.Write(data);
        cs.FlushFinalBlock();
        return (ms.ToArray(), aes.IV);
    }

    public static byte[] AesDecrypt(byte[] ciphertext, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        using var ms = new MemoryStream(ciphertext);
        using var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
        using var result = new MemoryStream();
        cs.CopyTo(result);
        return result.ToArray();
    }

    public static void CheckRSAKeys()
    {
        // Both Public & Private Keys Exist
        if (FileController.GetPrivateKey() != "" && FileController.GetPublicKey() != "")
        {
            return;
        }

        using var rsa = RSA.Create(2048);
        string publicKey = rsa.ExportRSAPublicKeyPem();
        string privateKey = rsa.ExportRSAPrivateKeyPem();
        FileController.SaveRSAKeys(publicKey, privateKey);
    }

    public static byte[] SignEntries(string entries)
    {
        var entriesBytes = Encoding.UTF8.GetBytes(entries);
        var privateKey = FileController.GetPrivateKey();

        return RSASign(entriesBytes, privateKey);
    }

    public static bool VerifyImportSignature(Dictionary<string, string> import)
    {
        var dataBytes = Encoding.UTF8.GetBytes(import["data"]);
        var sigBytes = Convert.FromBase64String(import["signature"]);

        var publicKey = FileController.GetPublicKey();

        return RSAVerify(dataBytes, sigBytes, publicKey);
    }

    public static async Task<string?> OAuthLogin()
    {
        var SecretFilePath = Environment.GetEnvironmentVariable("CLIENT_SECRET_PATH"); 
        if (!File.Exists(SecretFilePath))
        {
            return null;
        }

        var secrets = GoogleClientSecrets.FromFile(SecretFilePath).Secrets;
        var credential = await GoogleWebAuthorizationBroker.AuthorizeAsync(
            secrets,
            new[]
            {
                "https://www.googleapis.com/auth/userinfo.email",
                "https://www.googleapis.com/auth/userinfo.profile"
            },
            "user",
            CancellationToken.None
        );

        var oauth2Service = new Oauth2Service(new BaseClientService.Initializer
        {
            HttpClientInitializer = credential,
            ApplicationName = "Secure Vault"
        });

        var userInfo = await oauth2Service.Userinfo.Get().ExecuteAsync();

        CreateJWT(userInfo.Email, "OAuth");
        return userInfo.Email;
    }

    public static void CreateJWT(string sub, string authMethod)
    {
        TimeSpan lifetime = TimeSpan.FromSeconds(1800); // 30 mins
        var claims = new[] { 
            new Claim("sub", sub), 
            new Claim("authMethod", authMethod),
            new Claim("iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
        };

        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var jwtToken = new JwtSecurityToken(Issuer, Audience, claims,
            expires: DateTime.UtcNow.Add(lifetime), signingCredentials: credentials);
        
        savedToken = handler.WriteToken(jwtToken);
    }

    public static void ClearJWT()
    {
        savedToken = null;
    }

    public static (bool, string, string?) ValidateJWT()
    {
        try
        {
            var resp = handler.ValidateToken(savedToken, new TokenValidationParameters
            {
                ValidateIssuer = true, ValidIssuer = Issuer,
                ValidateAudience = true, ValidAudience = Audience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 }, // prevents the alg:none attack
                IssuerSigningKey = key
            }, out _);
            // I Don't think it's possible for the response to be null, but checking just in case...
            if (resp == null)
            {
                return (false, "Invalid JWT Token", null);
            }
            return (
                    true, 
                    resp.FindFirst("sub")?.Value ?? "Invalid Username",
                    resp.FindFirst("authMethod")?.Value ?? "Invalid Auth Method"
                );
        }
        catch (Exception ex) { return (false, ex.Message, null); }
    }

    private static byte[] RSASign(byte[] data, string privateKeyPem)
    {
        if (privateKeyPem == "")
        {
            return [];
        }

        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);
        return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    private static bool RSAVerify(byte[] data, byte[] signature, string publicKeyPem)
    {
        if (publicKeyPem == "")
        {
            return false;
        }

        using var rsa = RSA.Create();
        rsa.ImportFromPem(publicKeyPem);
        return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
}