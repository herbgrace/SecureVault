namespace SecureVault;

public record VaultEntry(Guid Id, string Site, string Username, string EncryptedPassword, string Iv, string Salt);