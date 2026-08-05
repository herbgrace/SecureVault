namespace SecureVault;

using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text.Unicode;
using System.Runtime.CompilerServices;

public static class SecurityController
{
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