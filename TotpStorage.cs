using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;

namespace SecureOTP
{
    /// <summary>
    /// Manages persistent storage of encrypted TOTP secrets with secure file operations.
    /// </summary>
    public class TotpStorage
    {
        private readonly string _storageFilePath;
        private readonly string _encryptionKey;
        private readonly ILogger<TotpStorage>? _logger;
        private readonly object _fileLock = new();

        /// <summary>
        /// Initializes a new instance of TotpStorage.
        /// </summary>
        /// <param name="encryptionKey">Master encryption key</param>
        /// <param name="storageFilePath">Path to the storage file (default: totp_accounts.json)</param>
        /// <param name="logger">Optional logger</param>
        public TotpStorage(string encryptionKey, string? storageFilePath = null, ILogger<TotpStorage>? logger = null)
        {
            if (string.IsNullOrWhiteSpace(encryptionKey))
                throw new ArgumentException("Encryption key cannot be null or empty", nameof(encryptionKey));

            _encryptionKey = encryptionKey;
            _storageFilePath = storageFilePath ?? "totp_accounts.json";
            _logger = logger;

            // Ensure storage directory exists
            var directory = Path.GetDirectoryName(_storageFilePath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
                _logger?.LogDebug("Created storage directory: {Directory}", directory);
            }
        }

        /// <summary>
        /// Stores an encrypted TOTP secret for an account.
        /// </summary>
        /// <param name="accountName">The account name</param>
        /// <param name="encryptedSecret">The encrypted TOTP secret</param>
        public void StoreAccount(string accountName, string encryptedSecret)
        {
            if (string.IsNullOrWhiteSpace(accountName))
                throw new ArgumentException("Account name cannot be null or empty", nameof(accountName));
            
            if (string.IsNullOrWhiteSpace(encryptedSecret))
                throw new ArgumentException("Encrypted secret cannot be null or empty", nameof(encryptedSecret));

            lock (_fileLock)
            {
                try
                {
                    var accounts = LoadAccountsInternal();
                    accounts[accountName] = new AccountData
                    {
                        EncryptedSecret = encryptedSecret,
                        CreatedAt = DateTimeOffset.UtcNow,
                        LastUsed = DateTimeOffset.UtcNow
                    };

                    SaveAccountsInternal(accounts);
                    _logger?.LogInformation("Stored TOTP account: {Account}", accountName);
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Failed to store TOTP account: {Account}", accountName);
                    throw new InvalidOperationException($"Failed to store account '{accountName}'", ex);
                }
            }
        }

        /// <summary>
        /// Retrieves an encrypted TOTP secret for an account.
        /// </summary>
        /// <param name="accountName">The account name</param>
        /// <returns>The encrypted secret, or null if not found</returns>
        public string? GetAccountSecret(string accountName)
        {
            if (string.IsNullOrWhiteSpace(accountName))
                throw new ArgumentException("Account name cannot be null or empty", nameof(accountName));

            lock (_fileLock)
            {
                try
                {
                    var accounts = LoadAccountsInternal();
                    
                    if (accounts.TryGetValue(accountName, out var accountData))
                    {
                        // Update last used timestamp
                        accountData.LastUsed = DateTimeOffset.UtcNow;
                        SaveAccountsInternal(accounts);
                        
                        _logger?.LogDebug("Retrieved TOTP secret for account: {Account}", accountName);
                        return accountData.EncryptedSecret;
                    }

                    _logger?.LogDebug("TOTP account not found: {Account}", accountName);
                    return null;
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Failed to retrieve TOTP account: {Account}", accountName);
                    throw new InvalidOperationException($"Failed to retrieve account '{accountName}'", ex);
                }
            }
        }

        /// <summary>
        /// Removes a TOTP account.
        /// </summary>
        /// <param name="accountName">The account name</param>
        /// <returns>True if removed, false if not found</returns>
        public bool RemoveAccount(string accountName)
        {
            if (string.IsNullOrWhiteSpace(accountName))
                throw new ArgumentException("Account name cannot be null or empty", nameof(accountName));

            lock (_fileLock)
            {
                try
                {
                    var accounts = LoadAccountsInternal();
                    var removed = accounts.Remove(accountName);
                    
                    if (removed)
                    {
                        SaveAccountsInternal(accounts);
                        _logger?.LogInformation("Removed TOTP account: {Account}", accountName);
                    }
                    else
                    {
                        _logger?.LogDebug("TOTP account not found for removal: {Account}", accountName);
                    }

                    return removed;
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Failed to remove TOTP account: {Account}", accountName);
                    throw new InvalidOperationException($"Failed to remove account '{accountName}'", ex);
                }
            }
        }

        /// <summary>
        /// Lists all stored account names.
        /// </summary>
        /// <returns>Collection of account names</returns>
        public IEnumerable<string> ListAccounts()
        {
            lock (_fileLock)
            {
                try
                {
                    var accounts = LoadAccountsInternal();
                    return accounts.Keys.ToArray(); // Return a copy to avoid concurrent modification
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Failed to list TOTP accounts");
                    throw new InvalidOperationException("Failed to list accounts", ex);
                }
            }
        }

        /// <summary>
        /// Gets detailed information about all accounts.
        /// </summary>
        /// <returns>Dictionary of account information</returns>
        public Dictionary<string, AccountInfo> GetAccountsInfo()
        {
            lock (_fileLock)
            {
                try
                {
                    var accounts = LoadAccountsInternal();
                    return accounts.ToDictionary(
                        kvp => kvp.Key,
                        kvp => new AccountInfo
                        {
                            AccountName = kvp.Key,
                            CreatedAt = kvp.Value.CreatedAt,
                            LastUsed = kvp.Value.LastUsed
                        }
                    );
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Failed to get accounts info");
                    throw new InvalidOperationException("Failed to get accounts info", ex);
                }
            }
        }

        /// <summary>
        /// Checks if an account exists.
        /// </summary>
        /// <param name="accountName">The account name</param>
        /// <returns>True if exists, false otherwise</returns>
        public bool AccountExists(string accountName)
        {
            if (string.IsNullOrWhiteSpace(accountName))
                return false;

            lock (_fileLock)
            {
                try
                {
                    var accounts = LoadAccountsInternal();
                    return accounts.ContainsKey(accountName);
                }
                catch (Exception ex)
                {
                    _logger?.LogError(ex, "Failed to check account existence: {Account}", accountName);
                    return false;
                }
            }
        }

        private Dictionary<string, AccountData> LoadAccountsInternal()
        {
            if (!File.Exists(_storageFilePath))
            {
                _logger?.LogDebug("Storage file not found, creating new: {FilePath}", _storageFilePath);
                return new Dictionary<string, AccountData>();
            }

            var json = File.ReadAllText(_storageFilePath);
            if (string.IsNullOrWhiteSpace(json))
            {
                return new Dictionary<string, AccountData>();
            }

            try
            {
                var accounts = JsonSerializer.Deserialize<Dictionary<string, AccountData>>(json);
                return accounts ?? new Dictionary<string, AccountData>();
            }
            catch (JsonException ex)
            {
                _logger?.LogWarning(ex, "Failed to deserialize accounts file, starting with empty storage");
                return new Dictionary<string, AccountData>();
            }
        }

        private void SaveAccountsInternal(Dictionary<string, AccountData> accounts)
        {
            var options = new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };

            var json = JsonSerializer.Serialize(accounts, options);
            
            // Write to temp file first, then move to ensure atomic operation
            var tempPath = _storageFilePath + ".tmp";
            File.WriteAllText(tempPath, json);
            
            if (File.Exists(_storageFilePath))
            {
                File.Delete(_storageFilePath);
            }
            
            File.Move(tempPath, _storageFilePath);

            // Set secure file permissions on Unix systems
            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            {
                try
                {
                    File.SetUnixFileMode(_storageFilePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Failed to set secure file permissions on {FilePath}", _storageFilePath);
                }
            }
        }

        /// <summary>
        /// Internal account data structure for JSON serialization.
        /// </summary>
        private class AccountData
        {
            [JsonPropertyName("encryptedSecret")]
            public string EncryptedSecret { get; set; } = string.Empty;

            [JsonPropertyName("createdAt")]
            public DateTimeOffset CreatedAt { get; set; }

            [JsonPropertyName("lastUsed")]
            public DateTimeOffset LastUsed { get; set; }
        }
    }

    /// <summary>
    /// Public account information (without sensitive data).
    /// </summary>
    public class AccountInfo
    {
        /// <summary>
        /// The account name.
        /// </summary>
        public string AccountName { get; set; } = string.Empty;

        /// <summary>
        /// When the account was created.
        /// </summary>
        public DateTimeOffset CreatedAt { get; set; }

        /// <summary>
        /// When the account was last used.
        /// </summary>
        public DateTimeOffset LastUsed { get; set; }
    }
}