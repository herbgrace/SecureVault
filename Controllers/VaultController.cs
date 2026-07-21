namespace SecureVault;

using System.Security.Cryptography;
using System.Text;
public static class VaultController
{
    public static void showMenu(string username)
    {
        while (true)
        {   
            Console.WriteLine($"""
            
            Welcome, {username}
            1. Change Password
            2. Add Entry
            3. List Entries
            4. View Entry's Password
            5. Delete Entry
            6. Exit
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
}