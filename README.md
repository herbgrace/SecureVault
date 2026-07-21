Welcome to the very secure vault!
In order to run the program, navigate to the home folder in a terminal and type "dotnet run"

In the main menu you will be given 3 options
1. Register new user
    Prompts you for a username & password
    Usernames must be unique, between 3-20 characters, and contain no spaces
    Passwords need to be at least 8 characters long, contain 1 uppercase, and 1 number
2. Login to existing user
    Prompts you for a username & password
    If the details are correct, will log you in and show the vault menu
    If the details are incorrect, will move you back to the main menu
3. Exit
    Closes the application

Inside the vault menu you will have 6 options
1. Change Password
    Prompts you for your current password
    If the password is incorrect, moves you back to the vault menu
    Otherwise, prompts your for a new password
    Same requirements here, 8+ characters, 1 uppercase, 1 number
    If everything is successful, updates your password and brings you back to the vault menu
2. Add an Entry
    Allows you to save a site's password to your account.
    Will prompt you for your master password then information relating to the site's account.
    Saves the encrypted password to your account's list in vault.json
3. List Entries
    Shows all the entries that are saved under your account
4. View Entry's Password
    Will prompt you for your account's master password.
    If given password is correct, will decrypt and show the password to the requested site.
5. Delete Entry
    After confirmation that you really do want to delete the saved information, will delete a saved site's information.
6. Exit
    Brings you back to the main menu