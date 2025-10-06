using System;
using System.Security.Cryptography;
using System.Text;
using OtpNet;
using Microsoft.Extensions.Logging;

namespace SecureOTP
{
    /// <summary>
    /// A secure TOTP (Time-based One-Time Password) service that provides encrypted secret storage
    /// and Google Authenticator compatibility.
    /// </summary>
    public class TotpService
    {
        private readonly ILogger<TotpService>? _logger;
        private readonly string _encryptionKey;

        /// <summary>
        /// Initializes a new instance of the TotpService with a custom encryption key.
        /// </summary>
        /// <param name="encryptionKey">The master encryption key for securing TOTP secrets</param>
        /// <param name="logger">Optional logger for diagnostic information</param>
        public TotpService(string encryptionKey, ILogger<TotpService>? logger = null)
        {
            if (string.IsNullOrWhiteSpace(encryptionKey))
                throw new ArgumentException("Encryption key cannot be null or empty", nameof(encryptionKey));
            
            _encryptionKey = encryptionKey;
            _logger = logger;
        }

        /// <summary>
        /// Initializes a new instance of the TotpService with an auto-generated encryption key.
        /// WARNING: Use this only for testing. In production, always provide a persistent encryption key.
        /// </summary>
        /// <param name="logger">Optional logger for diagnostic information</param>
        public TotpService(ILogger<TotpService>? logger = null)
        {
            _encryptionKey = GenerateEncryptionKey();
            _logger = logger;
            _logger?.LogWarning("TotpService initialized with auto-generated encryption key. This should only be used for testing.");
        }

        /// <summary>
        /// Generates a new TOTP secret and returns it encrypted.
        /// </summary>
        /// <returns>Base64-encoded encrypted secret</returns>
        public string GenerateNewSecret()
        {
            try
            {
                var secretBytes = KeyGeneration.GenerateRandomKey(20); // 160-bit key
                var secret = Base32Encoding.ToString(secretBytes);
                var encryptedSecret = EncryptSecret(secret);
                
                _logger?.LogDebug("Generated new TOTP secret");
                return encryptedSecret;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to generate new TOTP secret");
                throw new InvalidOperationException("Failed to generate TOTP secret", ex);
            }
        }

        /// <summary>
        /// Generates a TOTP code from an encrypted secret.
        /// </summary>
        /// <param name="encryptedSecret">The encrypted secret</param>
        /// <returns>6-digit TOTP code</returns>
        public string GenerateCode(string encryptedSecret)
        {
            if (string.IsNullOrWhiteSpace(encryptedSecret))
                throw new ArgumentException("Encrypted secret cannot be null or empty", nameof(encryptedSecret));

            try
            {
                var secret = DecryptSecret(encryptedSecret);
                var secretBytes = Base32Encoding.ToBytes(secret);
                var totp = new Totp(secretBytes);
                var code = totp.ComputeTotp();
                
                _logger?.LogDebug("Generated TOTP code");
                return code;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to generate TOTP code");
                throw new InvalidOperationException("Failed to generate TOTP code", ex);
            }
        }

        /// <summary>
        /// Verifies a TOTP code against an encrypted secret.
        /// </summary>
        /// <param name="encryptedSecret">The encrypted secret</param>
        /// <param name="code">The code to verify</param>
        /// <param name="windowSteps">Number of time steps to allow for clock skew (default: 1)</param>
        /// <returns>True if the code is valid, false otherwise</returns>
        public bool VerifyCode(string encryptedSecret, string code, int windowSteps = 1)
        {
            if (string.IsNullOrWhiteSpace(encryptedSecret))
                throw new ArgumentException("Encrypted secret cannot be null or empty", nameof(encryptedSecret));
            
            if (string.IsNullOrWhiteSpace(code))
                return false;

            try
            {
                var secret = DecryptSecret(encryptedSecret);
                var secretBytes = Base32Encoding.ToBytes(secret);
                var totp = new Totp(secretBytes);
                var isValid = totp.VerifyTotp(code, out _, new VerificationWindow(windowSteps, windowSteps));
                
                _logger?.LogDebug("TOTP code verification: {Result}", isValid ? "SUCCESS" : "FAILED");
                return isValid;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to verify TOTP code");
                return false;
            }
        }

        /// <summary>
        /// Gets the provisioning URI for QR code generation compatible with Google Authenticator.
        /// </summary>
        /// <param name="encryptedSecret">The encrypted secret</param>
        /// <param name="accountName">The account name (usually email or username)</param>
        /// <param name="issuer">The issuer name (your app/service name)</param>
        /// <returns>otpauth:// URI for QR code generation</returns>
        public string GetProvisioningUri(string encryptedSecret, string accountName, string issuer = "SecureOTP")
        {
            if (string.IsNullOrWhiteSpace(encryptedSecret))
                throw new ArgumentException("Encrypted secret cannot be null or empty", nameof(encryptedSecret));
            
            if (string.IsNullOrWhiteSpace(accountName))
                throw new ArgumentException("Account name cannot be null or empty", nameof(accountName));

            try
            {
                var secret = DecryptSecret(encryptedSecret);
                var uri = $"otpauth://totp/{Uri.EscapeDataString(accountName)}?secret={secret}&issuer={Uri.EscapeDataString(issuer)}";
                
                _logger?.LogDebug("Generated provisioning URI for account: {Account}", accountName);
                return uri;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to generate provisioning URI for account: {Account}", accountName);
                throw new InvalidOperationException("Failed to generate provisioning URI", ex);
            }
        }

        /// <summary>
        /// Imports an existing TOTP secret (plain text) and returns it encrypted.
        /// </summary>
        /// <param name="plainSecret">The plain text Base32 secret</param>
        /// <returns>Encrypted secret</returns>
        public string ImportSecret(string plainSecret)
        {
            if (string.IsNullOrWhiteSpace(plainSecret))
                throw new ArgumentException("Plain secret cannot be null or empty", nameof(plainSecret));

            try
            {
                // Validate the secret by trying to decode it
                Base32Encoding.ToBytes(plainSecret);
                
                var encryptedSecret = EncryptSecret(plainSecret);
                _logger?.LogDebug("Imported TOTP secret");
                return encryptedSecret;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to import TOTP secret");
                throw new InvalidOperationException("Failed to import TOTP secret. Ensure it's a valid Base32 string.", ex);
            }
        }

        /// <summary>
        /// Gets the remaining time in seconds until the current TOTP code expires.
        /// </summary>
        /// <returns>Seconds remaining for current code</returns>
        public int GetRemainingTimeForCurrentCode()
        {
            var unixTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var timeStep = 30; // TOTP uses 30-second time steps
            return (int)(timeStep - (unixTime % timeStep));
        }

        /// <summary>
        /// Encrypts a TOTP secret using AES-256.
        /// </summary>
        /// <param name="plainSecret">The plain text secret</param>
        /// <returns>Base64-encoded encrypted secret</returns>
        private string EncryptSecret(string plainSecret)
        {
            using var aes = Aes.Create();
            var key = DeriveKey(_encryptionKey);
            aes.Key = key;
            aes.GenerateIV();

            var encryptor = aes.CreateEncryptor();
            var plainBytes = Encoding.UTF8.GetBytes(plainSecret);
            var encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

            // Combine IV and encrypted data
            var result = new byte[aes.IV.Length + encryptedBytes.Length];
            Array.Copy(aes.IV, 0, result, 0, aes.IV.Length);
            Array.Copy(encryptedBytes, 0, result, aes.IV.Length, encryptedBytes.Length);

            return Convert.ToBase64String(result);
        }

        /// <summary>
        /// Decrypts a TOTP secret using AES-256.
        /// </summary>
        /// <param name="encryptedSecret">The encrypted secret</param>
        /// <returns>Plain text secret</returns>
        private string DecryptSecret(string encryptedSecret)
        {
            var encryptedData = Convert.FromBase64String(encryptedSecret);
            
            using var aes = Aes.Create();
            var key = DeriveKey(_encryptionKey);
            aes.Key = key;

            // Extract IV and encrypted bytes
            var iv = new byte[aes.IV.Length];
            var encryptedBytes = new byte[encryptedData.Length - iv.Length];
            Array.Copy(encryptedData, 0, iv, 0, iv.Length);
            Array.Copy(encryptedData, iv.Length, encryptedBytes, 0, encryptedBytes.Length);

            aes.IV = iv;
            var decryptor = aes.CreateDecryptor();
            var decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);

            return Encoding.UTF8.GetString(decryptedBytes);
        }

        /// <summary>
        /// Derives a 256-bit key from the master key using PBKDF2.
        /// </summary>
        /// <param name="masterKey">The master key</param>
        /// <returns>256-bit derived key</returns>
        private byte[] DeriveKey(string masterKey)
        {
            var salt = Encoding.UTF8.GetBytes("SecureOTP.Salt.2024"); // Use a consistent salt
            using var pbkdf2 = new Rfc2898DeriveBytes(masterKey, salt, 100000, HashAlgorithmName.SHA256);
            return pbkdf2.GetBytes(32); // 256-bit key
        }

        /// <summary>
        /// Generates a random encryption key.
        /// </summary>
        /// <returns>Base64-encoded encryption key</returns>
        private static string GenerateEncryptionKey()
        {
            var keyBytes = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(keyBytes);
            return Convert.ToBase64String(keyBytes);
        }
    }
}