using System;
using SecureOTP;

namespace SecureOTP.SandboxExample
{
    /// <summary>
    /// Example of using the sandboxed TOTP functionality.
    /// This can only be executed from within the application - no external access possible.
    /// </summary>
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("=== Sandboxed Google Authenticator Demo ===");
            Console.WriteLine("No master password required - internal execution only\n");

            try
            {
                // Example 1: Setup Google Authenticator for a user
                Console.WriteLine("🔧 Setting up Google Authenticator for user...");
                var userEmail = "john.doe@company.com";
                var appName = "MySecureApp";

                var (success, qrCode, message) = InternalTotpAPI.SetupGoogleAuthenticator(userEmail, appName);

                if (success)
                {
                    Console.WriteLine("✅ Setup successful!");
                    Console.WriteLine($"📱 QR Code for phone: {qrCode}");
                    Console.WriteLine($"📋 Instructions: User should scan this QR code with Google Authenticator");
                }
                else
                {
                    Console.WriteLine($"❌ Setup failed: {message}");
                    return;
                }

                // Example 2: Show current expected code
                Console.WriteLine("\n🔢 Current expected code:");
                var (codeSuccess, currentCode, remaining) = InternalTotpAPI.GetCurrentCode(userEmail);
                if (codeSuccess)
                {
                    Console.WriteLine($"📱 Phone should show: {currentCode}");
                    Console.WriteLine($"⏰ Expires in: {remaining} seconds");
                }

                // Example 3: Simulate user authentication
                Console.WriteLine("\n✅ Simulating user authentication...");
                
                // In real usage, this code would come from user input
                var userEnteredCode = currentCode; // Simulating correct code
                
                var (isValid, authMessage) = InternalTotpAPI.AuthenticateUser(userEmail, userEnteredCode);
                
                if (isValid)
                {
                    Console.WriteLine("🎉 Authentication SUCCESS!");
                    Console.WriteLine("✅ User is now logged in with 2FA verification");
                }
                else
                {
                    Console.WriteLine($"❌ Authentication failed: {authMessage}");
                }

                // Example 4: Test invalid code
                Console.WriteLine("\n🚫 Testing invalid code...");
                var (isInvalid, invalidMessage) = InternalTotpAPI.AuthenticateUser(userEmail, "000000");
                Console.WriteLine($"Invalid code result: {(isInvalid ? "✅ Accepted" : "❌ Rejected")} - {invalidMessage}");

                // Example 5: List all configured accounts
                Console.WriteLine("\n📋 Configured accounts:");
                var accounts = InternalTotpAPI.GetAccounts();
                foreach (var account in accounts)
                {
                    Console.WriteLine($"  • {account}");
                }

                Console.WriteLine("\n🔒 Security Features:");
                Console.WriteLine("✅ No master password exposure");
                Console.WriteLine("✅ Cannot be executed via terminal/SSH");
                Console.WriteLine("✅ Sandboxed execution only");
                Console.WriteLine("✅ AES-256 encrypted storage");
                Console.WriteLine("✅ Machine-specific key derivation");

            }
            catch (UnauthorizedAccessException ex)
            {
                Console.WriteLine($"🚫 Access Denied: {ex.Message}");
                Console.WriteLine("This demonstrates the sandbox working - external execution blocked!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error: {ex.Message}");
            }

            Console.WriteLine("\n🏁 Demo completed");
        }
    }
}