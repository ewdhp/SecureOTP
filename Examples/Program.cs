using System;
using SecureOTP;

namespace SecureOTP.Examples
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("🔐 SecureOTP Library Example");
            Console.WriteLine("============================");
            Console.WriteLine();

            // Initialize with encryption key
            var encryptionKey = "MySecureEncryptionKey12345678901234567890";
            var totpManager = new TotpManager(encryptionKey);

            try
            {
                // Example 1: Create new TOTP account
                Console.WriteLine("📱 Creating new TOTP account...");
                var accountName = $"demo-user-{DateTimeOffset.Now.ToUnixTimeSeconds()}@example.com";
                var result = totpManager.CreateAccount(accountName, "ExampleApp");
                
                Console.WriteLine($"✅ Account created: {result.AccountName}");
                Console.WriteLine($"📲 QR Code URI: {result.QrCodeUri}");
                Console.WriteLine();

                // Example 2: Generate current TOTP code
                Console.WriteLine("🔢 Generating current TOTP code...");
                var codeResult = totpManager.GenerateCode(accountName);
                Console.WriteLine($"📱 Current code: {codeResult.Code}");
                Console.WriteLine($"⏰ Expires in: {codeResult.RemainingSeconds} seconds");
                Console.WriteLine();

                // Example 3: Verify the generated code
                Console.WriteLine("✅ Verifying the generated code...");
                var verification = totpManager.VerifyCode(accountName, codeResult.Code);
                Console.WriteLine($"🔍 Verification result: {(verification.IsValid ? "VALID" : "INVALID")}");
                Console.WriteLine();

                // Example 4: Import existing TOTP secret
                Console.WriteLine("📥 Importing existing TOTP secret...");
                var importAccountName = "imported-service@example.com";
                var existingSecret = "JBSWY3DPEHPK3PXP"; // Example Base32 secret
                var importResult = totpManager.ImportAccount(importAccountName, existingSecret, "ImportedService");
                Console.WriteLine($"✅ Imported account: {importResult.AccountName}");
                Console.WriteLine();

                // Example 5: List all accounts
                Console.WriteLine("📋 Listing all accounts...");
                var accounts = totpManager.ListAccounts();
                foreach (var account in accounts)
                {
                    Console.WriteLine($"  • {account}");
                }
                Console.WriteLine();

                // Example 6: Get detailed account information
                Console.WriteLine("📊 Account information:");
                var accountsInfo = totpManager.GetAccountsInfo();
                foreach (var (name, info) in accountsInfo)
                {
                    Console.WriteLine($"  • {name}");
                    Console.WriteLine($"    Created: {info.CreatedAt:yyyy-MM-dd HH:mm:ss} UTC");
                    Console.WriteLine($"    Last used: {info.LastUsed:yyyy-MM-dd HH:mm:ss} UTC");
                }
                Console.WriteLine();

                // Example 7: Working with TotpService directly (without storage)
                Console.WriteLine("🔧 Using TotpService directly...");
                var totpService = new TotpService(encryptionKey);
                
                var directSecret = totpService.GenerateNewSecret();
                var directCode = totpService.GenerateCode(directSecret);
                var directQrUri = totpService.GetProvisioningUri(directSecret, "direct@example.com", "DirectApp");
                
                Console.WriteLine($"📱 Direct code: {directCode}");
                Console.WriteLine($"📲 Direct QR URI: {directQrUri}");
                Console.WriteLine();

                // Example 8: Time-based operations
                Console.WriteLine("⏰ Time-based operations...");
                Console.WriteLine($"📅 Current time: {DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
                Console.WriteLine($"⏳ Time remaining for current code: {totpService.GetRemainingTimeForCurrentCode()} seconds");
                Console.WriteLine();

                // Cleanup: Remove demo accounts
                Console.WriteLine("🧹 Cleaning up demo accounts...");
                totpManager.RemoveAccount(accountName);
                totpManager.RemoveAccount(importAccountName);
                Console.WriteLine("✅ Demo accounts removed");
                
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error: {ex.Message}");
                Console.WriteLine($"📍 Stack trace: {ex.StackTrace}");
            }

            Console.WriteLine();
            Console.WriteLine("🎉 Example completed!");
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }
    }
}