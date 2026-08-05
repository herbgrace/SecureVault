namespace SecureVault;

using System.ComponentModel.Design;
using System.Text.Json;
using System.Text.Unicode;

public static class FileController
{
    private const string USER_FILEPATH = "./Models/users.json";
    private const string VAULT_FILEPATH = "./Models/vault.json";
    private const string PRIVATE_KEY_PATH = "./Models/Keys/private_key.pem";
    private const string PUBLIC_KEY_PATH = "./Models/Keys/public_key.pem";
    private const string BASE_EXPORT_PATH = "./Exports";

    // Does the same thing as File.WriteAllText, but allows all file operations to be in this controller.
    public static void SaveFile(string path, string? contents)
    {
        contents = contents == null ? "" : contents;
        File.WriteAllText(path, contents);
    }

    public static void SaveUsers(Dictionary<string, User> users)
    {
        SaveFile(USER_FILEPATH, JsonSerializer.Serialize(users, new JsonSerializerOptions { WriteIndented = true }));
    }

    public static Dictionary<string, User> LoadUsers()
    {
        if (!File.Exists(USER_FILEPATH))
        {
            return new();
        }
        var json = File.ReadAllText(USER_FILEPATH);
        return JsonSerializer.Deserialize<Dictionary<string, User>>(json) ?? new();
    }

    public static List<VaultEntry>? LoadEntries(string username)
    {
        var json = LoadVaultJSON();
        return json.GetValueOrDefault(username);
    }

    public static VaultEntry? LoadEntry(string username, string site)
    {
        var existing = LoadEntries(username);
        if (existing == null) return null;
        return existing.Find(e => e.Site == site);
    }

    public static void SaveEntry(string username, VaultEntry entry)
    {
        List<VaultEntry> entries = LoadEntries(username) ?? new List<VaultEntry>();
        entries.Add(entry);
        SaveEntries(username, entries);
    }

    public static void SaveEntries(string username, List<VaultEntry> entries)
    {
        var vault = LoadVaultJSON();
        vault[username] = entries;
        SaveFile(VAULT_FILEPATH, JsonSerializer.Serialize(vault, new JsonSerializerOptions { WriteIndented = true }));
    }

    public static bool RemoveEntry(string username, string site)
    {
        var entries = LoadEntries(username);
        if (entries == null) return false;
        
        var siteToRemove = entries.Find(e => e.Site == site);
        if (siteToRemove == null) return false;

        entries.Remove(siteToRemove);
        SaveEntries(username, entries);
        return true;
    }

    public static Dictionary<string, List<VaultEntry>> LoadVaultJSON()
    {
        if (!File.Exists(VAULT_FILEPATH))
        {
            using (File.Create(VAULT_FILEPATH))
            {
                return new();
            }
        }
        var raw = File.ReadAllText(VAULT_FILEPATH);
        if (raw == "") {
            raw = "{}";
        }
        return JsonSerializer.Deserialize<Dictionary<string, List<VaultEntry>>>(raw) ?? new();
    }

    public static void MergeImport(string username, List<VaultEntry> entries)
    {
        var existing = LoadEntries(username) ?? new List<VaultEntry>();
        foreach (var entry in entries)
        {
            // Doesn't exist in the system already
            if (existing.Find(e => e.Id == entry.Id) == null)
            {
                existing.Add(entry);
            }
        }
        SaveEntries(username, existing);
    }

    public static void SaveRSAKeys(string publicKey, string privateKey)
    {
        File.WriteAllText(PUBLIC_KEY_PATH, publicKey);
        File.WriteAllText(PRIVATE_KEY_PATH, privateKey);
    }

    public static string GetPrivateKey()
    {
        if (!File.Exists(PRIVATE_KEY_PATH))
        {
            return "";
        }
        return File.ReadAllText(PRIVATE_KEY_PATH);
    }

    public static string GetPublicKey()
    {
        if (!File.Exists(PUBLIC_KEY_PATH))
        {
            return "";
        }
        return File.ReadAllText(PUBLIC_KEY_PATH);
    }

    public static void SaveExport(string username, string encryptedEntries)
    {
        int count = 0;
        while (File.Exists($"{BASE_EXPORT_PATH}/{username}{count}.json"))
        {
            count++;
        }

        SaveFile($"{BASE_EXPORT_PATH}/{username}{count}.json", encryptedEntries);
    }

    public static Dictionary<string, string> LoadExport(string path)
    {
        if (!File.Exists(path))
        {
            return new();
        }

        var raw = File.ReadAllText(path);
        if (raw == "") {
            raw = "{}";
        }
        return JsonSerializer.Deserialize<Dictionary<string, string>>(raw) ?? new();
    }
}