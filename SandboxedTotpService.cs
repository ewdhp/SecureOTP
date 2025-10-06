using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using OtpNet;
using Microsoft.Extensions.Logging;

namespace SecureOTP
{
    /// <summary>
    /// Sandboxed TOTP service that operates only within the application context.
    /// No external master password required - uses internal key derivation.
    /// </summary>
    public class SandboxedTotpService
    {
        private readonly string _internalKey;
        private readonly ILogger<SandboxedTotpService>? _logger;
        private static readonly string _keyFile = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            ".secureotp", "internal.key"
        );

        /// <summary>
        /// Initializes sandboxed TOTP service with internal key management.
        /// </summary>
        public SandboxedTotpService(ILogger<SandboxedTotpService>? logger = null)
        {
            _logger = logger;
            _internalKey = GetOrCreateInternalKey();
            _logger?.LogDebug("Sandboxed TOTP service initialized");
        }

        /// <summary>
        /// Creates a new TOTP account (only callable from within the application).
        /// </summary>
        /// <param name="accountName">Account identifier</param>
        /// <param name="issuer">Issuer name</param>
        /// <returns>TOTP setup result</returns>
        public TotpSetupResult CreateAccount(string accountName, string issuer = "SecureApp")
        {
            ValidateInternalExecution();

            try
            {
                var secret = GenerateSecret();
                var qrUri = GenerateQrUri(secret, accountName, issuer);
                
                // Store encrypted
                StoreAccountSecret(accountName, secret);

                _logger?.LogInformation("TOTP account created: {Account}", accountName);

                return new TotpSetupResult
                {
                    Success = true,
                    QrCodeUri = qrUri,
                    AccountName = accountName,
                    Message = "Account created successfully"
                };
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to create TOTP account");
                return new TotpSetupResult
                {
                    Success = false,
                    Message = $"Failed to create account: {ex.Message}"
                };
            }
        }

        /// <summary>
        /// Generates current TOTP code (only callable from within the application).
        /// </summary>
        /// <param name="accountName">Account to generate code for</param>
        /// <returns>Current TOTP code</returns>
        public TotpCodeResult GenerateCode(string accountName)
        {
            ValidateInternalExecution();

            try
            {
                var secret = GetAccountSecret(accountName);
                var secretBytes = Base32Encoding.ToBytes(secret);
                var totp = new Totp(secretBytes);
                var code = totp.ComputeTotp();
                var remainingSeconds = totp.RemainingSeconds();

                return new TotpCodeResult
                {
                    Success = true,
                    Code = code,
                    AccountName = accountName,
                    RemainingSeconds = remainingSeconds,
                    GeneratedAt = DateTimeOffset.UtcNow
                };
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to generate TOTP code for {Account}", accountName);
                return new TotpCodeResult
                {
                    Success = false,
                    Message = $"Failed to generate code: {ex.Message}"
                };
            }
        }

        /// <summary>
        /// Verifies a TOTP code (only callable from within the application).
        /// </summary>
        /// <param name="accountName">Account to verify</param>
        /// <param name="code">Code to verify</param>
        /// <returns>Verification result</returns>
        public TotpVerifyResult VerifyCode(string accountName, string code)
        {
            ValidateInternalExecution();

            try
            {
                var secret = GetAccountSecret(accountName);
                var secretBytes = Base32Encoding.ToBytes(secret);
                var totp = new Totp(secretBytes);
                var isValid = totp.VerifyTotp(code, out var timeStepMatched, window: TimeSpan.FromMinutes(1));

                return new TotpVerifyResult
                {
                    IsValid = isValid,
                    AccountName = accountName,
                    Code = code,
                    VerifiedAt = DateTimeOffset.UtcNow,
                    Message = isValid ? "Code is valid" : "Code is invalid"
                };
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to verify TOTP code for {Account}", accountName);
                return new TotpVerifyResult
                {
                    IsValid = false,
                    Message = $"Verification failed: {ex.Message}"
                };
            }
        }

        /// <summary>
        /// Lists all stored accounts (only callable from within the application).
        /// </summary>
        /// <returns>Array of account names</returns>
        public string[] ListAccounts()
        {
            ValidateInternalExecution();

            try
            {
                var storageDir = GetStorageDirectory();
                if (!Directory.Exists(storageDir))
                    return Array.Empty<string>();

                var files = Directory.GetFiles(storageDir, "*.dat");
                var accounts = new string[files.Length];
                
                for (int i = 0; i < files.Length; i++)
                {
                    accounts[i] = Path.GetFileNameWithoutExtension(files[i]);
                }

                return accounts;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to list accounts");
                return Array.Empty<string>();
            }
        }

        #region Internal Methods (Sandboxed)

        /// <summary>
        /// Validates that this method is being called from within the application context.
        /// Prevents external command-line or SSH access.
        /// </summary>
        private void ValidateInternalExecution()
        {
            var stackTrace = new System.Diagnostics.StackTrace();
            var callingAssembly = stackTrace.GetFrame(2)?.GetMethod()?.DeclaringType?.Assembly;
            var currentAssembly = System.Reflection.Assembly.GetExecutingAssembly();

            // Only allow execution from the same assembly or trusted assemblies
            if (callingAssembly != currentAssembly && !IsTrustedAssembly(callingAssembly))
            {
                throw new UnauthorizedAccessException("TOTP operations can only be executed from within the application context");
            }

            // Additional check: ensure we're not being called from a command-line context
            if (IsCommandLineExecution())
            {
                throw new UnauthorizedAccessException("Direct command-line access to TOTP operations is not permitted");
            }
        }

        private bool IsTrustedAssembly(System.Reflection.Assembly? assembly)
        {
            if (assembly == null) return false;
            
            // Add trusted assembly names here
            var trustedAssemblies = new[] { "SecureOTP", "YourMainApplication" };
            var assemblyName = assembly.GetName().Name;
            
            return trustedAssemblies.Contains(assemblyName);
        }

        private bool IsCommandLineExecution()
        {
            try
            {
                // Check if we're running in a console application with command-line args
                var args = Environment.GetCommandLineArgs();
                var processName = Environment.ProcessPath ?? "";
                
                // If launched directly via dotnet run or executable with args, block it
                return args.Length > 1 && (processName.Contains("dotnet") || processName.EndsWith(".exe"));
            }
            catch
            {
                return false; // If we can't determine, allow execution
            }
        }

        private string GetOrCreateInternalKey()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_keyFile)!);

                if (File.Exists(_keyFile))
                {
                    var encryptedKey = File.ReadAllBytes(_keyFile);
                    return DecryptInternalKey(encryptedKey);
                }
                else
                {
                    var key = GenerateRandomKey();
                    var encryptedKey = EncryptInternalKey(key);
                    File.WriteAllBytes(_keyFile, encryptedKey);
                    
                    // Set file permissions to be readable only by current user
                    if (Environment.OSVersion.Platform == PlatformID.Unix)
                    {
                        File.SetUnixFileMode(_keyFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                    }
                    
                    return key;
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to initialize internal key");
                throw new InvalidOperationException("Failed to initialize secure key storage", ex);
            }
        }

        private string GenerateSecret()
        {
            var secretBytes = new byte[20]; // 160 bits
            RandomNumberGenerator.Fill(secretBytes);
            return Base32Encoding.ToString(secretBytes);
        }

        private string GenerateQrUri(string secret, string accountName, string issuer)
        {
            return $"otpauth://totp/{Uri.EscapeDataString(accountName)}?secret={secret}&issuer={Uri.EscapeDataString(issuer)}&algorithm=SHA1&digits=6&period=30";
        }

        private void StoreAccountSecret(string accountName, string secret)
        {
            var storageDir = GetStorageDirectory();
            Directory.CreateDirectory(storageDir);

            var filePath = Path.Combine(storageDir, $"{accountName}.dat");
            var encryptedSecret = EncryptSecret(secret);
            
            File.WriteAllBytes(filePath, encryptedSecret);
            
            // Set secure file permissions
            if (Environment.OSVersion.Platform == PlatformID.Unix)
            {
                File.SetUnixFileMode(filePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }

        private string GetAccountSecret(string accountName)
        {
            var filePath = Path.Combine(GetStorageDirectory(), $"{accountName}.dat");
            if (!File.Exists(filePath))
                throw new ArgumentException($"Account '{accountName}' not found");

            var encryptedSecret = File.ReadAllBytes(filePath);
            return DecryptSecret(encryptedSecret);
        }

        private string GetStorageDirectory()
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                ".secureotp", "accounts"
            );
        }

        private byte[] EncryptSecret(string secret)
        {
            using var aes = Aes.Create();
            var keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(_internalKey));
            aes.Key = keyBytes;
            aes.GenerateIV();

            using var encryptor = aes.CreateEncryptor();
            var secretBytes = Encoding.UTF8.GetBytes(secret);
            var encrypted = encryptor.TransformFinalBlock(secretBytes, 0, secretBytes.Length);

            var result = new byte[aes.IV.Length + encrypted.Length];
            aes.IV.CopyTo(result, 0);
            encrypted.CopyTo(result, aes.IV.Length);

            return result;
        }

        private string DecryptSecret(byte[] encryptedData)
        {
            using var aes = Aes.Create();
            var keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(_internalKey));
            aes.Key = keyBytes;

            var iv = new byte[aes.IV.Length];
            var encrypted = new byte[encryptedData.Length - iv.Length];

            Array.Copy(encryptedData, 0, iv, 0, iv.Length);
            Array.Copy(encryptedData, iv.Length, encrypted, 0, encrypted.Length);

            aes.IV = iv;

            using var decryptor = aes.CreateDecryptor();
            var decrypted = decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);

            return Encoding.UTF8.GetString(decrypted);
        }

        private byte[] EncryptInternalKey(string key)
        {
            var keyBytes = Encoding.UTF8.GetBytes(key);
            var entropy = new byte[16];
            RandomNumberGenerator.Fill(entropy);

            // Use machine-specific encryption (Windows DPAPI or equivalent)
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                return ProtectedData.Protect(keyBytes, entropy, DataProtectionScope.CurrentUser);
            }
            else
            {
                // For non-Windows, use a simple XOR with machine identifier
                var machineKey = Environment.MachineName + Environment.UserName;
                var machineKeyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(machineKey));
                
                for (int i = 0; i < keyBytes.Length; i++)
                {
                    keyBytes[i] ^= machineKeyBytes[i % machineKeyBytes.Length];
                }
                
                return keyBytes;
            }
        }

        private string DecryptInternalKey(byte[] encryptedKey)
        {
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                var decrypted = ProtectedData.Unprotect(encryptedKey, null, DataProtectionScope.CurrentUser);
                return Encoding.UTF8.GetString(decrypted);
            }
            else
            {
                var machineKey = Environment.MachineName + Environment.UserName;
                var machineKeyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(machineKey));
                
                for (int i = 0; i < encryptedKey.Length; i++)
                {
                    encryptedKey[i] ^= machineKeyBytes[i % machineKeyBytes.Length];
                }
                
                return Encoding.UTF8.GetString(encryptedKey);
            }
        }

        private string GenerateRandomKey()
        {
            var keyBytes = new byte[32]; // 256 bits
            RandomNumberGenerator.Fill(keyBytes);
            return Convert.ToBase64String(keyBytes);
        }

        #endregion
    }

    #region Result Classes

    public class TotpSetupResult
    {
        public bool Success { get; set; }
        public string QrCodeUri { get; set; } = string.Empty;
        public string AccountName { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
    }

    public class TotpCodeResult
    {
        public bool Success { get; set; }
        public string Code { get; set; } = string.Empty;
        public string AccountName { get; set; } = string.Empty;
        public int RemainingSeconds { get; set; }
        public DateTimeOffset GeneratedAt { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    public class TotpVerifyResult
    {
        public bool IsValid { get; set; }
        public string AccountName { get; set; } = string.Empty;
        public string Code { get; set; } = string.Empty;
        public DateTimeOffset? VerifiedAt { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    #endregion
}