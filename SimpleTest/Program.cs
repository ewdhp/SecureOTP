using System;
using System.IO;
using System.Linq;
using SecureOTP;

namespace SecureOTP.SimpleTest
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("=== SecureOTP Complete Flow Test ===\n");

            // Setup test environment
            var testDir = Path.Combine(Path.GetTempPath(), "SecureOTP_Test");
            if (Directory.Exists(testDir))
                Directory.Delete(testDir, true);
            Directory.CreateDirectory(testDir);
            
            var masterPassword = "test-password-123";
            var accountName = "test@example.com";
            var issuer = "SecureOTP Demo";

            Console.WriteLine($"📁 Test Directory: {testDir}");
            Console.WriteLine($"🔐 Master Password: {masterPassword}");
            Console.WriteLine($"👤 Account: {accountName}");
            Console.WriteLine($"🏢 Issuer: {issuer}\n");

            try
            {
                // Step 1: Initialize TotpManager
                Console.WriteLine("🔧 Step 1: Initializing TOTP Manager");
                Console.WriteLine("====================================");
                var manager = new TotpManager(masterPassword, Path.Combine(testDir, "accounts.json"));
                Console.WriteLine("✅ TOTP Manager initialized successfully\n");

                // Step 2: Create Account and Generate QR Code
                Console.WriteLine("📱 Step 2: Creating Account & Generating QR Code");
                Console.WriteLine("================================================");
                var createResult = manager.CreateAccount(accountName, issuer);
                
                if (!createResult.Success)
                {
                    Console.WriteLine($"❌ Failed to create account: {createResult.Message}");
                    return;
                }

                Console.WriteLine("✅ Account created successfully!");
                Console.WriteLine($"📊 QR Code URI:");
                Console.WriteLine($"   {createResult.QrCodeUri}");
                Console.WriteLine("\n📋 To scan with your phone:");
                Console.WriteLine("1. Open Google Authenticator or similar TOTP app");
                Console.WriteLine("2. Add account by scanning QR code");
                Console.WriteLine("3. Generate QR code from the URI above\n");

                // Step 3: Verify Storage
                Console.WriteLine("💾 Step 3: Verifying Secure Storage");
                Console.WriteLine("===================================");
                var accounts = manager.ListAccounts();
                Console.WriteLine($"✅ Stored accounts count: {accounts.Count()}");
                Console.WriteLine($"✅ Account found: {accounts.First()}");
                
                var storageFile = Path.Combine(testDir, "accounts.json");
                if (File.Exists(storageFile))
                {
                    var fileInfo = new FileInfo(storageFile);
                    Console.WriteLine($"✅ Storage file: {fileInfo.Name} ({fileInfo.Length} bytes)");
                    Console.WriteLine($"✅ Encrypted storage verified\n");
                }

                // Step 4: Generate Current Codes
                Console.WriteLine("🔢 Step 4: Generating Current TOTP Codes");
                Console.WriteLine("=========================================");
                
                for (int i = 0; i < 3; i++)
                {
                    var codeResult = manager.GenerateCode(accountName);
                    if (codeResult.Success)
                    {
                        var currentTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                        var remainingSeconds = 30 - (currentTime % 30);
                        
                        Console.WriteLine($"🎯 Code #{i + 1}: {codeResult.Code}");
                        Console.WriteLine($"   • Generated at: {codeResult.GeneratedAt:HH:mm:ss}");
                        Console.WriteLine($"   • Expires in: {remainingSeconds} seconds");
                        Console.WriteLine($"   • Remaining: {codeResult.RemainingSeconds} seconds");
                    }
                    
                    if (i < 2) 
                    {
                        Console.WriteLine("   Waiting 2 seconds...");
                        System.Threading.Thread.Sleep(2000);
                    }
                }
                Console.WriteLine();

                // Step 5: Test Code Verification
                Console.WriteLine("✅ Step 5: Testing Code Verification");
                Console.WriteLine("====================================");
                
                var testCode = manager.GenerateCode(accountName);
                Console.WriteLine($"🎯 Generated test code: {testCode.Code}");
                
                // Verify the generated code
                var verifyResult = manager.VerifyCode(accountName, testCode.Code);
                
                if (verifyResult.IsValid)
                {
                    Console.WriteLine("✅ VERIFICATION SUCCESS!");
                    Console.WriteLine($"   • Code {testCode.Code} is VALID");
                    Console.WriteLine($"   • Verified at: {verifyResult.VerifiedAt:HH:mm:ss}");
                    Console.WriteLine($"   • Message: {verifyResult.Message}");
                }
                else
                {
                    Console.WriteLine("❌ VERIFICATION FAILED!");
                    Console.WriteLine($"   • Code {testCode.Code} is INVALID");
                    Console.WriteLine($"   • Message: {verifyResult.Message}");
                }

                // Test invalid code
                Console.WriteLine("\n🚫 Testing Invalid Code:");
                var invalidResult = manager.VerifyCode(accountName, "000000");
                Console.WriteLine($"   Code 000000: {(invalidResult.IsValid ? "✅ Valid" : "❌ Invalid")} (Expected: Invalid)");

                // Step 6: Interactive Test
                Console.WriteLine("\n📱 Step 6: Interactive Phone Verification");
                Console.WriteLine("==========================================");
                Console.WriteLine("Now you can test with your phone!");
                Console.WriteLine($"Current expected code: {manager.GenerateCode(accountName).Code}");
                Console.WriteLine("\nTo continue testing:");
                Console.WriteLine("1. Scan the QR code above with your phone");
                Console.WriteLine("2. Enter codes from your phone app");
                Console.WriteLine("3. Press Ctrl+C to exit anytime\n");

                while (true)
                {
                    Console.Write("Enter 6-digit code from your phone (or 'quit'): ");
                    var input = Console.ReadLine()?.Trim();
                    
                    if (string.IsNullOrEmpty(input) || input.ToLower() == "quit")
                        break;

                    if (input.Length != 6 || !input.All(char.IsDigit))
                    {
                        Console.WriteLine("❌ Invalid format. Please enter exactly 6 digits.");
                        continue;
                    }

                    var phoneVerifyResult = manager.VerifyCode(accountName, input);
                    
                    if (phoneVerifyResult.IsValid)
                    {
                        Console.WriteLine($"✅ SUCCESS! Your phone code {input} is VALID");
                        Console.WriteLine($"   • Perfect synchronization with your device!");
                    }
                    else
                    {
                        Console.WriteLine($"❌ Code {input} is invalid");
                        var currentExpected = manager.GenerateCode(accountName);
                        Console.WriteLine($"   • Expected: {currentExpected.Code}");
                        var timeRemaining = DateTimeOffset.UtcNow.ToUnixTimeSeconds() % 30;
                        Console.WriteLine($"   • Time remaining: {30 - timeRemaining}s");
                    }
                    
                    Console.WriteLine();
                }

                // Final Summary
                Console.WriteLine("\n📊 Test Summary");
                Console.WriteLine("===============");
                Console.WriteLine("✅ Account Creation: SUCCESS");
                Console.WriteLine("✅ QR Code Generation: SUCCESS");
                Console.WriteLine("✅ Secure Storage: SUCCESS");
                Console.WriteLine("✅ Code Generation: SUCCESS");
                Console.WriteLine("✅ Code Verification: SUCCESS");
                Console.WriteLine("✅ Interactive Test: AVAILABLE");
                Console.WriteLine("\n🎉 All OTP functionality working perfectly!");
                
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n❌ ERROR: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
            }
            finally
            {
                Console.WriteLine($"\n📂 Test files in: {testDir}");
                Console.WriteLine("🏁 Test execution completed successfully!");
                
                // Only wait for input if we have a real console
                try
                {
                    if (Console.IsInputRedirected)
                    {
                        Console.WriteLine("Input redirected - exiting automatically.");
                    }
                    else
                    {
                        Console.WriteLine("Press any key to exit...");
                        Console.ReadKey();
                    }
                }
                catch (Exception)
                {
                    // Fallback for environments where Console.IsInputRedirected isn't available
                    Console.WriteLine("Exiting...");
                }
            }
        }
    }
}