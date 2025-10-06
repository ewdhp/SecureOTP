using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;

namespace SecureOTP
{
    /// <summary>
    /// High-level manager that combines TotpService and TotpStorage for complete TOTP functionality.
    /// </summary>
    public class TotpManager
    {
        private readonly TotpService _totpService;
        private readonly TotpStorage _totpStorage;
        private readonly ILogger<TotpManager>? _logger;

        /// <summary>
        /// Initializes a new instance of TotpManager.
        /// </summary>
        /// <param name="encryptionKey">Master encryption key</param>
        /// <param name="storageFilePath">Optional custom storage file path</param>
        /// <param name="logger">Optional logger</param>
        public TotpManager(string encryptionKey, string? storageFilePath = null, ILogger<TotpManager>? logger = null)
        {
            _logger = logger;
            _totpService = new TotpService(encryptionKey, logger as ILogger<TotpService>);
            _totpStorage = new TotpStorage(encryptionKey, storageFilePath, logger as ILogger<TotpStorage>);
        }

        /// <summary>
        /// Creates a new TOTP account with a generated secret.
        /// </summary>
        /// <param name="accountName">The account name</param>
        /// <param name="issuer">The issuer name for QR code</param>
        /// <returns>TotpAccountResult with QR code and setup information</returns>
        public TotpAccountResult CreateAccount(string accountName, string issuer = "SecureOTP")
        {
            if (string.IsNullOrWhiteSpace(accountName))
                throw new ArgumentException("Account name cannot be null or empty", nameof(accountName));

            if (_totpStorage.AccountExists(accountName))
                throw new InvalidOperationException($"Account '{accountName}' already exists");

            try
            {
                var encryptedSecret = _totpService.GenerateNewSecret();
                var qrCodeUri = _totpService.GetProvisioningUri(encryptedSecret, accountName, issuer);
                
                _totpStorage.StoreAccount(accountName, encryptedSecret);
                
                _logger?.LogInformation("Created TOTP account: {Account}", accountName);

                return new TotpAccountResult
                {
                    AccountName = accountName,
                    QrCodeUri = qrCodeUri,
                    Success = true,
                    Message = "Account created successfully"
                };
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to create TOTP account: {Account}", accountName);
                throw new InvalidOperationException($"Failed to create account '{accountName}'", ex);
            }
        }

        /// <summary>
        /// Imports an existing TOTP secret for an account.
        /// </summary>
        /// <param name="accountName">The account name</param>
        /// <param name="plainSecret">The plain Base32 secret</param>
        /// <param name="issuer">The issuer name for QR code</param>
        /// <param name="overwrite">Whether to overwrite if account exists</param>
        /// <returns>TotpAccountResult with import information</returns>
        public TotpAccountResult ImportAccount(string accountName, string plainSecret, string issuer = "SecureOTP", bool overwrite = false)
        {
            if (string.IsNullOrWhiteSpace(accountName))
                throw new ArgumentException("Account name cannot be null or empty", nameof(accountName));

            if (string.IsNullOrWhiteSpace(plainSecret))
                throw new ArgumentException("Plain secret cannot be null or empty", nameof(plainSecret));

            if (!overwrite && _totpStorage.AccountExists(accountName))
                throw new InvalidOperationException($"Account '{accountName}' already exists. Use overwrite=true to replace it.");

            try
            {
                var encryptedSecret = _totpService.ImportSecret(plainSecret);
                var qrCodeUri = _totpService.GetProvisioningUri(encryptedSecret, accountName, issuer);
                
                _totpStorage.StoreAccount(accountName, encryptedSecret);
                
                _logger?.LogInformation("Imported TOTP account: {Account}", accountName);

                return new TotpAccountResult
                {
                    AccountName = accountName,
                    QrCodeUri = qrCodeUri,
                    Success = true,
                    Message = overwrite ? "Account imported and overwritten successfully" : "Account imported successfully"
                };
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to import TOTP account: {Account}", accountName);
                throw new InvalidOperationException($"Failed to import account '{accountName}'", ex);
            }
        }

        /// <summary>
        /// Generates the current TOTP code for an account.
        /// </summary>
        /// <param name="accountName">The account name</param>
        /// <returns>TotpCodeResult with the current code and timing information</returns>
        public TotpCodeResult GenerateCode(string accountName)
        {
            if (string.IsNullOrWhiteSpace(accountName))
                throw new ArgumentException("Account name cannot be null or empty", nameof(accountName));

            var encryptedSecret = _totpStorage.GetAccountSecret(accountName);
            if (encryptedSecret == null)
                throw new InvalidOperationException($"Account '{accountName}' not found");

            try
            {
                var code = _totpService.GenerateCode(encryptedSecret);
                var remainingTime = _totpService.GetRemainingTimeForCurrentCode();
                
                _logger?.LogDebug("Generated TOTP code for account: {Account}", accountName);

                return new TotpCodeResult
                {
                    AccountName = accountName,
                    Code = code,
                    RemainingSeconds = remainingTime,
                    GeneratedAt = DateTimeOffset.UtcNow,
                    Success = true
                };
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to generate TOTP code for account: {Account}", accountName);
                throw new InvalidOperationException($"Failed to generate code for account '{accountName}'", ex);
            }
        }

        /// <summary>
        /// Verifies a TOTP code for an account.
        /// </summary>
        /// <param name="accountName">The account name</param>
        /// <param name="code">The code to verify</param>
        /// <param name="windowSteps">Time window for verification (default: 1)</param>
        /// <returns>TotpVerificationResult with verification outcome</returns>
        public TotpVerificationResult VerifyCode(string accountName, string code, int windowSteps = 1)
        {
            if (string.IsNullOrWhiteSpace(accountName))
                throw new ArgumentException("Account name cannot be null or empty", nameof(accountName));

            if (string.IsNullOrWhiteSpace(code))
            {
                return new TotpVerificationResult
                {
                    AccountName = accountName,
                    Code = code,
                    IsValid = false,
                    Message = "Code cannot be empty"
                };
            }

            var encryptedSecret = _totpStorage.GetAccountSecret(accountName);
            if (encryptedSecret == null)
            {
                return new TotpVerificationResult
                {
                    AccountName = accountName,
                    Code = code,
                    IsValid = false,
                    Message = $"Account '{accountName}' not found"
                };
            }

            try
            {
                var isValid = _totpService.VerifyCode(encryptedSecret, code, windowSteps);
                
                _logger?.LogInformation("TOTP verification for account {Account}: {Result}", accountName, isValid ? "SUCCESS" : "FAILED");

                return new TotpVerificationResult
                {
                    AccountName = accountName,
                    Code = code,
                    IsValid = isValid,
                    VerifiedAt = DateTimeOffset.UtcNow,
                    Message = isValid ? "Code is valid" : "Code is invalid or expired"
                };
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to verify TOTP code for account: {Account}", accountName);
                
                return new TotpVerificationResult
                {
                    AccountName = accountName,
                    Code = code,
                    IsValid = false,
                    Message = "Verification failed due to internal error"
                };
            }
        }

        /// <summary>
        /// Gets the QR code URI for an existing account.
        /// </summary>
        /// <param name="accountName">The account name</param>
        /// <param name="issuer">The issuer name</param>
        /// <returns>QR code URI</returns>
        public string GetQrCodeUri(string accountName, string issuer = "SecureOTP")
        {
            if (string.IsNullOrWhiteSpace(accountName))
                throw new ArgumentException("Account name cannot be null or empty", nameof(accountName));

            var encryptedSecret = _totpStorage.GetAccountSecret(accountName);
            if (encryptedSecret == null)
                throw new InvalidOperationException($"Account '{accountName}' not found");

            return _totpService.GetProvisioningUri(encryptedSecret, accountName, issuer);
        }

        /// <summary>
        /// Removes an account.
        /// </summary>
        /// <param name="accountName">The account name</param>
        /// <returns>True if removed, false if not found</returns>
        public bool RemoveAccount(string accountName)
        {
            if (string.IsNullOrWhiteSpace(accountName))
                throw new ArgumentException("Account name cannot be null or empty", nameof(accountName));

            var removed = _totpStorage.RemoveAccount(accountName);
            
            if (removed)
            {
                _logger?.LogInformation("Removed TOTP account: {Account}", accountName);
            }

            return removed;
        }

        /// <summary>
        /// Lists all account names.
        /// </summary>
        /// <returns>Collection of account names</returns>
        public IEnumerable<string> ListAccounts()
        {
            return _totpStorage.ListAccounts();
        }

        /// <summary>
        /// Gets detailed information about all accounts.
        /// </summary>
        /// <returns>Dictionary of account information</returns>
        public Dictionary<string, AccountInfo> GetAccountsInfo()
        {
            return _totpStorage.GetAccountsInfo();
        }

        /// <summary>
        /// Checks if an account exists.
        /// </summary>
        /// <param name="accountName">The account name</param>
        /// <returns>True if exists, false otherwise</returns>
        public bool AccountExists(string accountName)
        {
            return _totpStorage.AccountExists(accountName);
        }
    }

    /// <summary>
    /// Result of TOTP account creation or import operation.
    /// </summary>
    public class TotpAccountResult
    {
        /// <summary>
        /// The account name.
        /// </summary>
        public string AccountName { get; set; } = string.Empty;

        /// <summary>
        /// The QR code URI for Google Authenticator.
        /// </summary>
        public string QrCodeUri { get; set; } = string.Empty;

        /// <summary>
        /// Whether the operation was successful.
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// Result message.
        /// </summary>
        public string Message { get; set; } = string.Empty;
    }

    /// <summary>
    /// Result of TOTP code generation.
    /// </summary>
    public class TotpCodeResult
    {
        /// <summary>
        /// The account name.
        /// </summary>
        public string AccountName { get; set; } = string.Empty;

        /// <summary>
        /// The generated TOTP code.
        /// </summary>
        public string Code { get; set; } = string.Empty;

        /// <summary>
        /// Seconds remaining until code expires.
        /// </summary>
        public int RemainingSeconds { get; set; }

        /// <summary>
        /// When the code was generated.
        /// </summary>
        public DateTimeOffset GeneratedAt { get; set; }

        /// <summary>
        /// Whether the generation was successful.
        /// </summary>
        public bool Success { get; set; }
    }

    /// <summary>
    /// Result of TOTP code verification.
    /// </summary>
    public class TotpVerificationResult
    {
        /// <summary>
        /// The account name.
        /// </summary>
        public string AccountName { get; set; } = string.Empty;

        /// <summary>
        /// The code that was verified.
        /// </summary>
        public string Code { get; set; } = string.Empty;

        /// <summary>
        /// Whether the code is valid.
        /// </summary>
        public bool IsValid { get; set; }

        /// <summary>
        /// When the verification was performed.
        /// </summary>
        public DateTimeOffset? VerifiedAt { get; set; }

        /// <summary>
        /// Verification message.
        /// </summary>
        public string Message { get; set; } = string.Empty;
    }

    /// <summary>
    /// Result of TOTP setup operations.
    /// </summary>
    public class TotpSetupResult
    {
        public bool Success { get; set; }
        public string QrCodeUri { get; set; } = string.Empty;
        public string AccountName { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
    }

    /// <summary>
    /// Result of TOTP verification operations for compatibility.
    /// </summary>
    public class TotpVerifyResult
    {
        public bool IsValid { get; set; }
        public string AccountName { get; set; } = string.Empty;
        public string Code { get; set; } = string.Empty;
        public DateTimeOffset? VerifiedAt { get; set; }
        public string Message { get; set; } = string.Empty;
    }
}