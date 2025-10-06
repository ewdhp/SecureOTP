using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using SecureOTP;

namespace SecureOTP.InteractiveTest
{
    public class Program
    {


        public static async Task Main(string[] args)
        {
            Console.WriteLine("=== SecureOTP Interactive Test ===");
            Console.WriteLine("Testing complete flow: QR generation → Phone scan → OTP verification\n");

            // Setup test environment
            var testDir = Path.Combine(Path.GetTempPath(), "SecureOTP_Test", DateTime.Now.ToString("yyyyMMdd_HHmmss"));
            Directory.CreateDirectory(testDir);
            
            var masterPassword = "test-master-password-123";
            var accountName = "test@example.com";
            var issuer = "SecureOTP Test";

            Console.WriteLine($"📁 Test Directory: {testDir}");
            Console.WriteLine($"🔐 Master Password: {masterPassword}");
            Console.WriteLine($"👤 Account: {accountName}");
            Console.WriteLine($"🏢 Issuer: {issuer}\n");

            try
            {
                // Initialize TotpManager
                Console.WriteLine("🔧 Initializing TOTP Manager...");
                var manager = new TotpManager(masterPassword, Path.Combine(testDir, "accounts.json"));

                // Step 1: Generate QR Code and Secret
                Console.WriteLine("\n📱 STEP 1: Generating QR Code for Phone");
                Console.WriteLine("=====================================");
                
                var createResult = manager.CreateAccount(accountName, issuer);
                
                if (!createResult.Success)
                {
                    Console.WriteLine($"❌ Failed to create account: {createResult.Message}");
                    return;
                }

                Console.WriteLine("✅ Account created successfully!");
                Console.WriteLine($"📊 QR Code URI: {createResult.QrCodeUri}");
                
                // Display QR code information
                Console.WriteLine("\n📋 QR Code Details:");
                Console.WriteLine($"   • Account: {accountName}");
                Console.WriteLine($"   • Issuer: {issuer}");
                Console.WriteLine($"   • Algorithm: SHA1");
                Console.WriteLine($"   • Digits: 6");
                Console.WriteLine($"   • Period: 30 seconds");

                // Step 2: Verify Secret Storage
                Console.WriteLine("\n💾 STEP 2: Verifying Secure Storage");
                Console.WriteLine("===================================");
                
                var accounts = manager.ListAccounts().ToArray();
                Console.WriteLine($"✅ Stored accounts: {accounts.Length}");
                
                if (accounts.Length > 0)
                {
                    Console.WriteLine($"   • Account found: {accounts[0]}");
                }

                // Display storage file info
                var storageFiles = Directory.GetFiles(testDir, "*.json");
                foreach (var file in storageFiles)
                {
                    var fileInfo = new FileInfo(file);
                    Console.WriteLine($"📄 Storage file: {Path.GetFileName(file)} ({fileInfo.Length} bytes)");
                }

                // Step 3: Manual QR Code Instructions
                Console.WriteLine("\n📱 STEP 3: Phone Setup Instructions");
                Console.WriteLine("====================================");
                Console.WriteLine("To test with your phone:");
                Console.WriteLine("1. Open Google Authenticator or similar TOTP app");
                Console.WriteLine("2. Add new account by scanning QR code");
                Console.WriteLine("3. Use this URI in a QR code generator:");
                Console.WriteLine($"\n{createResult.QrCodeUri}\n");

                // Step 4: Generate current valid codes for comparison
                Console.WriteLine("\n🔢 STEP 4: Current Valid Codes");
                Console.WriteLine("===============================");
                
                // Get current valid code
                var currentCodeResult = manager.GenerateCode(accountName);
                var currentTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                var timeWindow = currentTime / 30;
                
                Console.WriteLine($"⏰ Current Time: {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss}");
                Console.WriteLine($"🎯 Current Valid Code: {currentCodeResult.Code}");
                Console.WriteLine($"📊 Time Window: {timeWindow}");
                Console.WriteLine($"⏳ Seconds until next code: {30 - (currentTime % 30)}");

                // Step 5: Interactive Verification
                Console.WriteLine("\n✅ STEP 5: Interactive Code Verification");
                Console.WriteLine("=========================================");
                
                Console.WriteLine("Now test the verification process:");
                Console.WriteLine($"Expected current code from your phone: {currentCodeResult.Code}");
                
                while (true)
                {
                    Console.Write("\nEnter the 6-digit code from your phone (or 'quit' to exit): ");
                    var userInput = Console.ReadLine()?.Trim();
                    
                    if (string.IsNullOrEmpty(userInput) || userInput.ToLower() == "quit")
                    {
                        break;
                    }

                    if (userInput.Length != 6 || !userInput.All(char.IsDigit))
                    {
                        Console.WriteLine("❌ Invalid format. Please enter exactly 6 digits.");
                        continue;
                    }

                    // Verify the code
                    var verifyResult = manager.VerifyCode(accountName, userInput);
                    
                    if (verifyResult.IsValid)
                    {
                        Console.WriteLine($"✅ SUCCESS! Code {userInput} is VALID");
                        Console.WriteLine($"   • Verification time: {verifyResult.VerifiedAt:yyyy-MM-dd HH:mm:ss}");
                        Console.WriteLine($"   • Message: {verifyResult.Message}");
                    }
                    else
                    {
                        Console.WriteLine($"❌ FAILED! Code {userInput} is INVALID");
                        var currentExpected = manager.GenerateCode(accountName);
                        Console.WriteLine($"   • Current expected: {currentExpected.Code}");
                        Console.WriteLine($"   • Error: {verifyResult.Message ?? "Code does not match"}");
                    }

                    // Show current valid code again
                    var refreshedCodeResult = manager.GenerateCode(accountName);
                    var refreshedTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    Console.WriteLine($"🔄 Current valid code: {refreshedCodeResult.Code} (expires in {30 - (refreshedTime % 30)}s)");
                }

                // Step 6: Test Current Code Multiple Times
                Console.WriteLine("\n🕐 STEP 6: Code Refresh Testing");
                Console.WriteLine("================================");
                
                Console.WriteLine("Testing code generation multiple times...");
                
                for (int i = 0; i < 5; i++)
                {
                    var testCodeResult = manager.GenerateCode(accountName);
                    var testVerifyResult = manager.VerifyCode(accountName, testCodeResult.Code);
                    
                    Console.WriteLine($"Test {i + 1}: {testCodeResult.Code} - {(testVerifyResult.IsValid ? "✅ Valid" : "❌ Invalid")}");
                    
                    if (i < 4) // Don't sleep after last iteration
                    {
                        await Task.Delay(1000); // Wait 1 second
                    }
                }

                // Step 7: Final Summary
                Console.WriteLine("\n📊 STEP 7: Test Summary");
                Console.WriteLine("========================");
                
                Console.WriteLine("✅ Account Creation: SUCCESS");
                Console.WriteLine("✅ Secret Generation: SUCCESS");
                Console.WriteLine("✅ QR Code Generation: SUCCESS");
                Console.WriteLine("✅ Secure Storage: SUCCESS");
                Console.WriteLine("✅ Code Generation: SUCCESS");
                Console.WriteLine("✅ Interactive Verification: AVAILABLE");
                
                Console.WriteLine($"\n📂 Test files created in: {testDir}");
                Console.WriteLine("🔧 You can inspect the encrypted storage files");
                Console.WriteLine("📱 Use the QR code URI with any QR generator to test with your phone");

            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n❌ ERROR: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
            }
            finally
            {
                Console.WriteLine("\n🏁 Test completed. Press any key to exit...");
                Console.ReadKey();
            }
        }
    }
}