using System;
using System.IO;
using SecureOTP;

namespace SecureOTP.QRTest
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("=== SecureOTP QR Code Generation Test ===");
            Console.WriteLine("Verifying QR code display for phone scanning\n");

            var testDir = Path.Combine(Path.GetTempPath(), "QR_Test");
            if (Directory.Exists(testDir)) Directory.Delete(testDir, true);
            Directory.CreateDirectory(testDir);

            try
            {
                Console.WriteLine("🔧 Initializing TOTP Manager...");
                var manager = new TotpManager("test-master-key", Path.Combine(testDir, "qr_accounts.json"));
                Console.WriteLine("✅ Manager initialized\n");

                Console.WriteLine("📱 GENERATING QR CODE FOR PHONE");
                Console.WriteLine("===============================");
                
                var account = "user@example.com";
                var issuer = "MyApp";
                
                Console.WriteLine($"Creating account: {account}");
                Console.WriteLine($"Issuer: {issuer}");
                
                var result = manager.CreateAccount(account, issuer);
                
                if (result.Success)
                {
                    Console.WriteLine("✅ QR Code generated successfully!\n");
                    
                    Console.WriteLine("📊 QR CODE URI (Ready for scanning):");
                    Console.WriteLine("=====================================");
                    Console.WriteLine(result.QrCodeUri);
                    Console.WriteLine();
                    
                    Console.WriteLine("📱 PHONE SETUP INSTRUCTIONS:");
                    Console.WriteLine("=============================");
                    Console.WriteLine("1. Open Google Authenticator on your phone");
                    Console.WriteLine("2. Tap the '+' button to add an account");
                    Console.WriteLine("3. Choose 'Scan a QR code'");
                    Console.WriteLine("4. Generate a QR code from the URI above using:");
                    Console.WriteLine("   • qr-code-generator.com");
                    Console.WriteLine("   • Any QR code generator website");
                    Console.WriteLine("   • Or use the URI directly in compatible apps");
                    Console.WriteLine();
                    
                    Console.WriteLine("🔍 QR CODE DETAILS:");
                    Console.WriteLine("===================");
                    
                    // Parse the URI to show details
                    var uri = result.QrCodeUri;
                    Console.WriteLine($"• Protocol: otpauth://totp/");
                    Console.WriteLine($"• Account: {account}");
                    Console.WriteLine($"• Issuer: {issuer}");
                    
                    // Extract secret from URI
                    var secretMatch = System.Text.RegularExpressions.Regex.Match(uri, @"secret=([A-Z2-7]+)");
                    if (secretMatch.Success)
                    {
                        var secret = secretMatch.Groups[1].Value;
                        Console.WriteLine($"• Secret Length: {secret.Length} characters");
                        Console.WriteLine($"• Secret Format: Base32 encoded");
                        Console.WriteLine($"• Secret Sample: {secret.Substring(0, 8)}...");
                    }
                    
                    Console.WriteLine("• Algorithm: SHA1 (Google Authenticator compatible)");
                    Console.WriteLine("• Digits: 6");
                    Console.WriteLine("• Period: 30 seconds");
                    
                    Console.WriteLine();
                    Console.WriteLine("🎯 VERIFICATION:");
                    Console.WriteLine("================");
                    
                    // Generate and display current code
                    var codeResult = manager.GenerateCode(account);
                    Console.WriteLine($"✅ Current TOTP code: {codeResult.Code}");
                    Console.WriteLine($"✅ Generated at: {codeResult.GeneratedAt:HH:mm:ss}");
                    Console.WriteLine($"✅ Expires in: {codeResult.RemainingSeconds} seconds");
                    Console.WriteLine();
                    
                    Console.WriteLine("📋 NEXT STEPS:");
                    Console.WriteLine("==============");
                    Console.WriteLine("1. Your phone will now generate the same codes");
                    Console.WriteLine($"2. Expected phone display: {codeResult.Code}");
                    Console.WriteLine("3. Codes change every 30 seconds");
                    Console.WriteLine("4. Server and phone should always match");
                    
                    Console.WriteLine("\n🎉 QR CODE READY FOR PHONE SCANNING!");
                }
                else
                {
                    Console.WriteLine($"❌ Failed to generate QR code: {result.Message}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error: {ex.Message}");
            }
            finally
            {
                Console.WriteLine($"\n📂 Test files: {testDir}");
            }
        }
    }
}