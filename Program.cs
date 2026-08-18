using System.ComponentModel;
using System.Security.Cryptography;
using Microsoft.VisualBasic;
using SecureVault;

FileController.LoadEnv();

while (true)
{
    Console.WriteLine("""
    1. Register new user
    2. Login to existing user
    3. Login with Google
    4. Exit
    """);
    switch(Console.ReadLine())
    {
        case "1":
            registerUser();
            break;
        case "2":
            loginUser();
            break;
        case "3":
            await googleLogin();
            break; 
        case "4":
            return;
        default:
            Console.WriteLine("Invalid Input");
            break;
    }
}

void registerUser()
{
    var existing = FileController.LoadUsers();

    Console.Write("Enter username: ");
    string name = Console.ReadLine()?.Trim() ?? "";
    if (name.Length < 3 || name.Length > 20 || name.Contains(" "))
    {
        Console.WriteLine("Invalid username");
    }
    if (existing.ContainsKey(name))
    {
        Console.WriteLine("Username already taken");
        return;
    }

    Console.Write("Enter password (8+ chars, 1+ digit, 1+ uppercase): ");
    string password = Console.ReadLine()?.Trim() ?? "";
    if (!SecurityController.PasswordFollowsConstraints(password))
    {
        Console.WriteLine("Invalid Password");
        return;
    }

    string salt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    existing.Add(name, new User(salt, SecurityController.SaltedHash(salt, password)));

    FileController.SaveUsers(existing);
    Console.WriteLine("New user added\n");
}

void loginUser()
{
    Console.Write("Enter username: ");
    string username = Console.ReadLine()?.Trim() ?? "";
    Console.Write("Enter password: ");
    string password = Console.ReadLine()?.Trim() ?? "";

    if (!SecurityController.IsCorrectPassword(username, password))
    {   
        Console.WriteLine("Invalid Credentials");
        return;
    } 

    SecurityController.CreateJWT(username, "Username/Password");
    VaultController.showMenu(username);
}

async Task googleLogin()
{
    string? username = await SecurityController.OAuthLogin();
    if (username == null)
    {
        Console.WriteLine("Unable to login with Google at this time, please try again later or contact a developer if the problem persists.");
        return;
    }

    var existing = FileController.LoadUsers();
    if (!existing.ContainsKey(username))
    {
        // User doesn't exist in the system, need to set a vault password
        string password = "";
        do 
        {
            Console.Write("Enter the master password you want to use for Secure Vault: ");
            password = Console.ReadLine() ?? "";
        } 
        while (!SecurityController.PasswordFollowsConstraints(password));

        string salt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        existing.Add(username, new User(salt, SecurityController.SaltedHash(salt, password)));
        FileController.SaveUsers(existing);
    }

    VaultController.showMenu(username);
}