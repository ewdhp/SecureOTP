using System;
using Microsoft.Extensions.Logging;

namespace SecureOTP
{
    /// <summary>
    /// Internal TOTP API that can only be called from within the application.
    /// No external password required - fully sandboxed execution.
    /// </summary>
    public static class InternalTotpAPI
    {
        private static readonly SandboxedTotpService _service = new();
        private static readonly object _lock = new();

        /// <summary>
        /// Creates a new TOTP account (internal use only).
        /// Can only be called from within the application - not from terminal/SSH.
        /// </summary>
        /// <param name="accountName">Account identifier</param>
        /// <param name="issuer">Application/service name</param>
        /// <returns>Setup result with QR code</returns>
        public static TotpSetupResult CreateAccount(string accountName, string issuer = "SecureApp")
        {
            lock (_lock)
            {
                return _service.CreateAccount(accountName, issuer);
            }
        }

        /// <summary>
        /// Generates current TOTP code (internal use only).
        /// Can only be called from within the application - not from terminal/SSH.
        /// </summary>
        /// <param name="accountName">Account to generate code for</param>
        /// <returns>Current 6-digit TOTP code</returns>
        public static TotpCodeResult GenerateCurrentCode(string accountName)
        {
            lock (_lock)
            {
                return _service.GenerateCode(accountName);
            }
        }

        /// <summary>
        /// Verifies a TOTP code (internal use only).
        /// Can only be called from within the application - not from terminal/SSH.
        /// </summary>
        /// <param name="accountName">Account to verify</param>
        /// <param name="code">6-digit code to verify</param>
        /// <returns>Verification result</returns>
        public static TotpVerifyResult VerifyCode(string accountName, string code)
        {
            lock (_lock)
            {
                return _service.VerifyCode(accountName, code);
            }
        }

        /// <summary>
        /// Lists all configured accounts (internal use only).
        /// Can only be called from within the application - not from terminal/SSH.
        /// </summary>
        /// <returns>Array of account names</returns>
        public static string[] GetAccounts()
        {
            lock (_lock)
            {
                return _service.ListAccounts();
            }
        }

        /// <summary>
        /// Complete workflow: Create account and get QR code for phone setup.
        /// This is the main method for setting up Google Authenticator.
        /// </summary>
        /// <param name="userEmail">User's email address</param>
        /// <param name="appName">Your application name</param>
        /// <returns>QR code URI and setup information</returns>
        public static (bool Success, string QrCode, string Message) SetupGoogleAuthenticator(string userEmail, string appName)
        {
            try
            {
                var result = CreateAccount(userEmail, appName);
                
                if (result.Success)
                {
                    return (true, result.QrCodeUri, "QR code generated successfully. User can scan with Google Authenticator.");
                }
                else
                {
                    return (false, "", $"Setup failed: {result.Message}");
                }
            }
            catch (UnauthorizedAccessException)
            {
                return (false, "", "Access denied: This function can only be called from within the application");
            }
            catch (Exception ex)
            {
                return (false, "", $"Setup failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Complete workflow: Verify user's phone code for authentication.
        /// This is the main method for validating Google Authenticator codes.
        /// </summary>
        /// <param name="userEmail">User's email address</param>
        /// <param name="phoneCode">6-digit code from user's phone</param>
        /// <returns>Authentication result</returns>
        public static (bool IsValid, string Message) AuthenticateUser(string userEmail, string phoneCode)
        {
            try
            {
                var result = VerifyCode(userEmail, phoneCode);
                
                if (result.IsValid)
                {
                    return (true, "Authentication successful");
                }
                else
                {
                    return (false, "Invalid code - authentication failed");
                }
            }
            catch (UnauthorizedAccessException)
            {
                return (false, "Access denied: This function can only be called from within the application");
            }
            catch (Exception ex)
            {
                return (false, $"Authentication failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Gets current expected code for debugging/testing (internal use only).
        /// </summary>
        /// <param name="userEmail">User's email address</param>
        /// <returns>Current expected code and expiration info</returns>
        public static (bool Success, string Code, int SecondsRemaining) GetCurrentCode(string userEmail)
        {
            try
            {
                var result = GenerateCurrentCode(userEmail);
                
                if (result.Success)
                {
                    return (true, result.Code, result.RemainingSeconds);
                }
                else
                {
                    return (false, "", 0);
                }
            }
            catch (UnauthorizedAccessException)
            {
                return (false, "Access denied", 0);
            }
            catch (Exception)
            {
                return (false, "", 0);
            }
        }
    }
}