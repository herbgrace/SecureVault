namespace SecureVault;

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
public static class VaultController
{
    public static void showMenu(string username)
    {
        // Ensure that public & private keys are generated
        SecurityController.CheckRSAKeys();
        while (true)
        {   
            Console.WriteLine($"""
            Welcome, {username}
            1. Change Password
            2. Add Entry
            3. List Entries
            4. View Entry's Password
            5. Delete Entry
            6. Export Entries
            7. Load Exported File
            8. Exit
            """);

            switch (Console.ReadLine())
            {
                case "1":
                    ChangePassword(username);
                    break;
                case "2":
                    AddEntry(username);
                    break;
                case "3":
                    ListEntries(username);
                    break;
                case "4":
                    ViewEntryPassword(username);
                    break;
                case "5":
                    DeleteEntry(username);
                    break;
                case "6":
                    ExportEntries(username);
                    break;
                case "7":
                    LoadExport(username);
                    break;
                case "8":
                    return;
                default:
                    Console.WriteLine("Invalid option");
                    break;
            }
        }
    }

    private static void ChangePassword(string username)
    {
        var existing = FileController.LoadUsers();
        var current = existing.GetValueOrDefault(username);
        if (current == null)
        {
            Console.WriteLine("How did this even happen???");
            return;
        }

        // Verify old password
        Console.Write("Enter your current password: ");
        string oldPass = Console.ReadLine()?.Trim() ?? "";

        if (!CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(current.hash),
            Encoding.UTF8.GetBytes(SecurityController.SaltedHash(current.salt, oldPass))
        ))
        {
            Console.WriteLine("Invalid Credentials");
            return;
        }

        // Change to new password
        Console.Write("Enter your new password (8+ characters, 1+ digit, 1+ capital): ");
        string newPass = Console.ReadLine()?.Trim() ?? "";
        if (!SecurityController.PasswordFollowsConstraints(newPass))
        {
            Console.WriteLine("Invalid new password");
            return;
        }

        string salt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        existing[username] = new User(salt, SecurityController.SaltedHash(salt, newPass));
        
        FileController.SaveUsers(existing);
        Console.WriteLine("Password updated!");
    }

    private static void AddEntry(string username)
    {
        Console.Write("Enter your master password: ");
        var mPass = Console.ReadLine() ?? "";
        if (!SecurityController.IsCorrectPassword(username, mPass))
        {
            Console.WriteLine("Invalid Password.");
            return;
        }

        Console.Write("Enter the website: ");
        var site = Console.ReadLine() ?? "";
        Console.Write("Enter the username: ");
        var entryUsername = Console.ReadLine() ?? "";
        Console.Write("Enter the site's password: ");
        var password = Console.ReadLine() ?? "";

        Guid guid = Guid.NewGuid();
        var salt = RandomNumberGenerator.GetBytes(32);
        var key = SecurityController.DeriveKey(mPass, salt);
        var (ciphertext, iv) = SecurityController.AesEncrypt(Encoding.UTF8.GetBytes(password), key);

        // Guid Id, string site, string username, string encryptedPassword, string iv, string salt
        VaultEntry entry = new VaultEntry(
            Id: guid, 
            Site: site, 
            Username: entryUsername, 
            EncryptedPassword: Convert.ToBase64String(ciphertext), 
            Iv: Convert.ToBase64String(iv), 
            Salt: Convert.ToBase64String(salt)
            );

        FileController.SaveEntry(username, entry);
    }

    private static void ListEntries(string username)
    {
        var entries = FileController.LoadEntries(username);
        if (entries == null)
        {
            Console.WriteLine("No entries found.");
            return;
        }

        foreach (var entry in entries)
        {  
            Console.WriteLine($"Site: {entry.Site}");
            Console.WriteLine($"Username: {entry.Username}\n");
        }
    }

    private static void ViewEntryPassword(string username)
    {
        Console.Write("Enter your master password: ");
        string password = Console.ReadLine() ?? "";

        if (!SecurityController.IsCorrectPassword(username, password))
        {
            Console.WriteLine("Invalid Password");
            return;
        }

        Console.Write("Enter the site you wish to view: ");
        string site = Console.ReadLine() ?? "";
        var siteOBJ = FileController.LoadEntry(username, site);
        if (siteOBJ == null)
        {
            Console.WriteLine("Cannot find the specified site");
            return;
        }

        var ciphertext = Convert.FromBase64String(siteOBJ.EncryptedPassword);
        var salt = Convert.FromBase64String(siteOBJ.Salt);
        var key = SecurityController.DeriveKey(password, salt);
        var iv = Convert.FromBase64String(siteOBJ.Iv);

        var plainPass = Encoding.UTF8.GetString(SecurityController.AesDecrypt(ciphertext, key, iv));

        Console.WriteLine($"Saved Password: {plainPass}");
    }

    private static void DeleteEntry(string username)
    {
        Console.Write("Enter the site you wish to delete: ");
        var site = Console.ReadLine() ?? "";

        Console.WriteLine("Type \"CONFIRM\" to confirm deletion");
        if (!(Console.ReadLine() == "CONFIRM"))
        {
            Console.WriteLine("Invalid Confirmation");
            return;
        }

        if (FileController.RemoveEntry(username, site))
        {
            Console.WriteLine("Entry Removed Successfully");
        } else
        {
            Console.WriteLine("Error Occured When Removing Entry (Check Your Spelling of the Site)");
        }
    }

    private static void ExportEntries(string username)
    {
        var serializer = new JsonSerializerOptions { WriteIndented = true };
        var contents = new Dictionary<string, string>();

        var entries = FileController.LoadEntries(username) ?? new List<VaultEntry>();
        var entriesString = JsonSerializer.Serialize(entries, serializer);

        var signed = SecurityController.SignEntries(entriesString);
        var signedString = Convert.ToBase64String(signed);
        
        contents.Add("data", entriesString);
        contents.Add("signature", signedString);
        contents.Add("exportedAt", DateTime.Now.ToString());
        contents.Add("exportedBy", username);

        var contentsString = JsonSerializer.Serialize(contents, serializer);
        FileController.SaveExport(username, contentsString);
        Console.WriteLine("Exported Entries Successfully");
    }

    private static void LoadExport(string username)
    {
        Console.Write("Enter the path to the import: ");
        string path = Console.ReadLine() ?? "";

        var export = FileController.LoadExport(path);

        if (!SecurityController.VerifyImportSignature(export))
        {
            Console.WriteLine("Signature failed, unable to import entries.");
            return;
        }

        Console.WriteLine("Signature succeeded. Importing entries");
        var data = export["data"];
        var entries = JsonSerializer.Deserialize<List<VaultEntry>>(data) ?? null;
        if (entries == null)
        {
            Console.WriteLine("Error parsing entries.");
            return;
        }

        FileController.MergeImport(username, entries);
        Console.WriteLine("Successfully imported new entries.");
    }
}