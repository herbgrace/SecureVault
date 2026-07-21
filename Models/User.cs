namespace SecureVault;

public record User (string salt, string hash);