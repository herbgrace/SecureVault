namespace SecureVault;

using System.Text.Json;

public static class FileController
{
    private const string USER_FILEPATH = "./Models/users.json";
    private const string VAULT_FILEPATH = "./Models/vault.json";

    public static void SaveUsers(Dictionary<string, User> users)
    {
        File.WriteAllText(USER_FILEPATH, JsonSerializer.Serialize(users, new JsonSerializerOptions { WriteIndented = true }));
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
        File.WriteAllText(VAULT_FILEPATH, JsonSerializer.Serialize(vault, new JsonSerializerOptions { WriteIndented = true }));
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
}