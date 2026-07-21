namespace SecureVault;

using System.Text;
using System.Security.Cryptography;

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
}