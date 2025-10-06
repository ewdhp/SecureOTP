using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using SecureOTP;

namespace DirectoryVaultCLI
{
    /// <summary>
    /// Command-line interface for Universal Secure Command Vault with Directory Encryption
    /// Provides interactive OTP-protected directory encryption and management
    /// </summary>
    class Program
    {
        private static SecureCommandVaultWithDirectories? _vault;
        private static string? _sessionId;

        static async Task Main(string[] args)
        {
            Console.WriteLine("🗂️  Secure Directory Vault CLI");
            Console.WriteLine("==============================");
            Console.WriteLine("OTP-Protected Directory Encryption & Management\n");

            try
            {
                await RunDirectoryVaultCLI();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error: {ex.Message}");
            }
            finally
            {
                _vault?.Dispose();
            }
        }

        static async Task RunDirectoryVaultCLI()
        {
            // Initialize vault
            Console.Write("🔐 Enter vault encryption key: ");
            var encryptionKey = ReadPassword();
            
            _vault = new SecureCommandVaultWithDirectories(encryptionKey);
            Console.WriteLine("✅ Vault initialized\n");

            while (true)
            {
                Console.WriteLine("📋 Directory Vault Commands:");
                Console.WriteLine("============================");
                Console.WriteLine("1. 📱 Setup TOTP Authentication");
                Console.WriteLine("2. 🔑 Login with TOTP");
                Console.WriteLine("3. 📁 Encrypt Directory");
                Console.WriteLine("4. 📤 Extract Directory");
                Console.WriteLine("5. 📋 List Encrypted Directories");
                Console.WriteLine("6. 🗑️  Remove Directory");
                Console.WriteLine("7. 📊 Show Vault Statistics");
                Console.WriteLine("8. 🚪 Exit\n");

                Console.Write("Select command (1-8): ");
                var choice = Console.ReadLine();

                try
                {
                    switch (choice)
                    {
                        case "1":
                            await SetupAuthentication();
                            break;
                        case "2":
                            await LoginWithTOTP();
                            break;
                        case "3":
                            await EncryptDirectory();
                            break;
                        case "4":
                            await ExtractDirectory();
                            break;
                        case "5":
                            await ListDirectories();
                            break;
                        case "6":
                            await RemoveDirectory();
                            break;
                        case "7":
                            await ShowVaultStatistics();
                            break;
                        case "8":
                            Console.WriteLine("👋 Goodbye!");
                            return;
                        default:
                            Console.WriteLine("❌ Invalid choice. Please select 1-8.\n");
                            break;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"❌ Error: {ex.Message}\n");
                }

                Console.WriteLine("\nPress any key to continue...");
                Console.ReadKey();
                Console.Clear();
            }
        }

        static async Task SetupAuthentication()
        {
            Console.WriteLine("\n📱 TOTP Authentication Setup");
            Console.WriteLine("============================");
            
            Console.Write("Enter account name (e.g., admin@company.com): ");
            var accountName = Console.ReadLine();
            
            if (string.IsNullOrWhiteSpace(accountName))
            {
                Console.WriteLine("❌ Account name is required");
                return;
            }

            Console.Write("Enter issuer name (default: SecureDirectoryVault): ");
            var issuer = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(issuer))
                issuer = "SecureDirectoryVault";

            Console.WriteLine("\n🔄 Setting up TOTP...");
            var result = await _vault!.SetupVaultAuthentication(accountName, issuer);

            if (result.Success)
            {
                Console.WriteLine("✅ TOTP setup successful!");
                Console.WriteLine($"\n📱 Scan this QR code with Google Authenticator:");
                Console.WriteLine($"🔗 {result.QrCodeUri}");
                Console.WriteLine("\nOr manually enter the setup key in your authenticator app.");
            }
            else
            {
                Console.WriteLine($"❌ Setup failed: {result.Message}");
            }
        }

        static async Task LoginWithTOTP()
        {
            Console.WriteLine("\n🔑 TOTP Authentication");
            Console.WriteLine("======================");
            
            Console.Write("Enter TOTP code from your authenticator app: ");
            var totpCode = Console.ReadLine();
            
            if (string.IsNullOrWhiteSpace(totpCode))
            {
                Console.WriteLine("❌ TOTP code is required");
                return;
            }

            Console.WriteLine("🔄 Authenticating...");
            var result = await _vault!.AuthenticateForAccess(totpCode);

            if (result.Success)
            {
                _sessionId = result.SessionId;
                Console.WriteLine("✅ Authentication successful!");
                Console.WriteLine($"🎫 Session ID: {_sessionId}");
                Console.WriteLine($"⏰ Expires: {result.ExpiresAt:yyyy-MM-dd HH:mm:ss}");
                Console.WriteLine($"📁 Available directories: {_vault.GetEncryptedDirectories(_sessionId).Count}");
            }
            else
            {
                Console.WriteLine($"❌ Authentication failed: {result.Message}");
                _sessionId = null;
            }
        }

        static async Task EncryptDirectory()
        {
            if (!IsAuthenticated())
                return;

            Console.WriteLine("\n📁 Encrypt Directory");
            Console.WriteLine("===================");
            
            Console.Write("Enter directory path to encrypt: ");
            var directoryPath = Console.ReadLine();
            
            if (string.IsNullOrWhiteSpace(directoryPath) || !Directory.Exists(directoryPath))
            {
                Console.WriteLine("❌ Invalid directory path");
                return;
            }

            Console.Write("Enter vault name for this directory: ");
            var vaultName = Console.ReadLine();
            
            if (string.IsNullOrWhiteSpace(vaultName))
            {
                Console.WriteLine("❌ Vault name is required");
                return;
            }

            Console.Write("Enter description (optional): ");
            var description = Console.ReadLine() ?? "";

            Console.Write("Preserve directory structure? (y/n, default: y): ");
            var preserveInput = Console.ReadLine()?.ToLower();
            var preserveStructure = preserveInput != "n";

            Console.Write("Enter exclude patterns (comma-separated, optional): ");
            var excludeInput = Console.ReadLine();
            var excludePatterns = string.IsNullOrWhiteSpace(excludeInput) 
                ? null 
                : excludeInput.Split(',', StringSplitOptions.RemoveEmptyEntries)
                             .Select(p => p.Trim()).ToArray();

            Console.WriteLine("\n🔄 Encrypting directory...");
            Console.WriteLine($"📂 Source: {directoryPath}");
            Console.WriteLine($"🏷️  Vault Name: {vaultName}");
            Console.WriteLine($"📋 Description: {description}");
            Console.WriteLine($"🏗️  Preserve Structure: {preserveStructure}");
            if (excludePatterns != null && excludePatterns.Length > 0)
            {
                Console.WriteLine($"🚫 Exclude Patterns: {string.Join(", ", excludePatterns)}");
            }

            var result = await _vault!.RegisterSecureDirectory(
                _sessionId!, directoryPath, vaultName, description, preserveStructure, excludePatterns);

            if (result.Success)
            {
                Console.WriteLine("✅ Directory encrypted successfully!");
                Console.WriteLine($"📊 Files encrypted: {result.FileCount}");
                Console.WriteLine($"💾 Total size: {result.TotalSize:N0} bytes");
                Console.WriteLine($"📁 Vault name: {result.DirectoryName}");
            }
            else
            {
                Console.WriteLine($"❌ Encryption failed: {result.Message}");
            }
        }

        static async Task ExtractDirectory()
        {
            if (!IsAuthenticated())
                return;

            Console.WriteLine("\n📤 Extract Directory");
            Console.WriteLine("===================");
            
            // List available directories first
            var directories = _vault!.GetEncryptedDirectories(_sessionId!);
            if (directories.Count == 0)
            {
                Console.WriteLine("❌ No encrypted directories found in vault");
                return;
            }

            Console.WriteLine("📋 Available directories:");
            for (int i = 0; i < directories.Count; i++)
            {
                var dir = directories[i];
                Console.WriteLine($"  {i + 1}. {dir.Name} ({dir.FileCount} files, {dir.TotalSize:N0} bytes)");
            }

            Console.Write("\nSelect directory number or enter vault name: ");
            var selection = Console.ReadLine();
            
            string? vaultName = null;
            if (int.TryParse(selection, out int index) && index > 0 && index <= directories.Count)
            {
                vaultName = directories[index - 1].Name;
            }
            else if (!string.IsNullOrWhiteSpace(selection))
            {
                vaultName = selection;
            }

            if (string.IsNullOrWhiteSpace(vaultName))
            {
                Console.WriteLine("❌ Invalid selection");
                return;
            }

            Console.Write("Enter extraction path: ");
            var extractPath = Console.ReadLine();
            
            if (string.IsNullOrWhiteSpace(extractPath))
            {
                Console.WriteLine("❌ Extraction path is required");
                return;
            }

            var overwrite = false;
            if (Directory.Exists(extractPath))
            {
                Console.Write("Directory exists. Overwrite? (y/n): ");
                overwrite = Console.ReadLine()?.ToLower() == "y";
            }

            Console.WriteLine($"\n🔄 Extracting '{vaultName}' to '{extractPath}'...");
            
            var result = await _vault!.ExtractSecureDirectory(_sessionId!, vaultName, extractPath, overwrite);

            if (result.Success)
            {
                Console.WriteLine("✅ Directory extracted successfully!");
                Console.WriteLine($"📁 Vault: {result.DirectoryName}");
                Console.WriteLine($"📂 Extract Path: {result.ExtractPath}");
                Console.WriteLine($"📊 Files extracted: {result.ExtractedFiles}");
            }
            else
            {
                Console.WriteLine($"❌ Extraction failed: {result.Message}");
            }
        }

        static async Task ListDirectories()
        {
            if (!IsAuthenticated())
                return;

            Console.WriteLine("\n📋 Encrypted Directories");
            Console.WriteLine("========================");
            
            var directories = _vault!.GetEncryptedDirectories(_sessionId!);
            
            if (directories.Count == 0)
            {
                Console.WriteLine("📭 No encrypted directories found in vault");
                return;
            }

            Console.WriteLine($"📂 Found {directories.Count} encrypted directories:\n");
            
            foreach (var dir in directories.OrderBy(d => d.Name))
            {
                Console.WriteLine($"🗂️  {dir.Name}");
                Console.WriteLine($"   📝 Description: {dir.Description}");
                Console.WriteLine($"   📊 Files: {dir.FileCount:N0}");
                Console.WriteLine($"   💾 Size: {dir.TotalSize:N0} bytes ({FormatFileSize(dir.TotalSize)})");
                Console.WriteLine($"   📅 Registered: {dir.RegisteredAt:yyyy-MM-dd HH:mm:ss}");
                Console.WriteLine($"   🏗️  Structure: {(dir.PreserveStructure ? "Preserved" : "Flattened")}");
                if (dir.ExcludePatterns.Length > 0)
                {
                    Console.WriteLine($"   🚫 Exclusions: {string.Join(", ", dir.ExcludePatterns)}");
                }
                Console.WriteLine();
            }

            var totalFiles = directories.Sum(d => d.FileCount);
            var totalSize = directories.Sum(d => d.TotalSize);
            Console.WriteLine($"📊 Total: {totalFiles:N0} files, {totalSize:N0} bytes ({FormatFileSize(totalSize)})");
        }

        static async Task RemoveDirectory()
        {
            if (!IsAuthenticated())
                return;

            Console.WriteLine("\n🗑️ Remove Directory");
            Console.WriteLine("===================");
            
            // List available directories first
            var directories = _vault!.GetEncryptedDirectories(_sessionId!);
            if (directories.Count == 0)
            {
                Console.WriteLine("❌ No encrypted directories found in vault");
                return;
            }

            Console.WriteLine("📋 Available directories:");
            for (int i = 0; i < directories.Count; i++)
            {
                var dir = directories[i];
                Console.WriteLine($"  {i + 1}. {dir.Name} ({dir.FileCount} files)");
            }

            Console.Write("\nSelect directory number or enter vault name: ");
            var selection = Console.ReadLine();
            
            string? vaultName = null;
            if (int.TryParse(selection, out int index) && index > 0 && index <= directories.Count)
            {
                vaultName = directories[index - 1].Name;
            }
            else if (!string.IsNullOrWhiteSpace(selection))
            {
                vaultName = selection;
            }

            if (string.IsNullOrWhiteSpace(vaultName))
            {
                Console.WriteLine("❌ Invalid selection");
                return;
            }

            Console.Write($"⚠️  Are you sure you want to remove '{vaultName}'? (y/n): ");
            if (Console.ReadLine()?.ToLower() != "y")
            {
                Console.WriteLine("🚫 Operation cancelled");
                return;
            }

            Console.WriteLine($"🔄 Removing '{vaultName}' from vault...");
            
            var success = await _vault!.RemoveEncryptedDirectory(_sessionId!, vaultName);

            if (success)
            {
                Console.WriteLine("✅ Directory removed successfully!");
            }
            else
            {
                Console.WriteLine("❌ Failed to remove directory");
            }
        }

        static async Task ShowVaultStatistics()
        {
            if (!IsAuthenticated())
                return;

            Console.WriteLine("\n📊 Vault Statistics");
            Console.WriteLine("==================");
            
            var directories = _vault!.GetEncryptedDirectories(_sessionId!);
            var commands = _vault!.GetAvailableCommands(_sessionId!);

            Console.WriteLine($"🗂️  Encrypted Directories: {directories.Count}");
            Console.WriteLine($"⚡ Encrypted Commands: {commands.Count}");
            
            if (directories.Count > 0)
            {
                var totalFiles = directories.Sum(d => d.FileCount);
                var totalSize = directories.Sum(d => d.TotalSize);
                var avgFileSize = totalFiles > 0 ? totalSize / totalFiles : 0;
                
                Console.WriteLine("\n📁 Directory Statistics:");
                Console.WriteLine($"   📊 Total Files: {totalFiles:N0}");
                Console.WriteLine($"   💾 Total Size: {totalSize:N0} bytes ({FormatFileSize(totalSize)})");
                Console.WriteLine($"   📈 Average File Size: {avgFileSize:N0} bytes ({FormatFileSize(avgFileSize)})");
                Console.WriteLine($"   📅 Oldest Entry: {directories.Min(d => d.RegisteredAt):yyyy-MM-dd HH:mm:ss}");
                Console.WriteLine($"   📅 Newest Entry: {directories.Max(d => d.RegisteredAt):yyyy-MM-dd HH:mm:ss}");
                
                var preservedCount = directories.Count(d => d.PreserveStructure);
                Console.WriteLine($"   🏗️  Structure Preserved: {preservedCount}/{directories.Count}");
                
                var withExclusions = directories.Count(d => d.ExcludePatterns.Length > 0);
                Console.WriteLine($"   🚫 With Exclusions: {withExclusions}/{directories.Count}");
            }
            
            if (commands.Count > 0)
            {
                var totalCommandSize = commands.Sum(c => c.FileSize);
                Console.WriteLine("\n⚡ Command Statistics:");
                Console.WriteLine($"   💾 Total Command Size: {totalCommandSize:N0} bytes ({FormatFileSize(totalCommandSize)})");
            }

            Console.WriteLine($"\n🎫 Session Information:");
            Console.WriteLine($"   🆔 Session ID: {_sessionId}");
            Console.WriteLine($"   ⏰ Session Active: ✅");
            Console.WriteLine($"   🔒 Security Level: Military Grade");
        }

        static string FormatFileSize(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len = len / 1024;
            }
            return $"{len:0.##} {sizes[order]}";
        }

        static bool IsAuthenticated()
        {
            if (string.IsNullOrWhiteSpace(_sessionId))
            {
                Console.WriteLine("❌ Not authenticated. Please login first (option 2)");
                return false;
            }
            return true;
        }

        static string ReadPassword()
        {
            string password = "";
            ConsoleKeyInfo key;
            do
            {
                key = Console.ReadKey(true);
                if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
                {
                    password += key.KeyChar;
                    Console.Write("*");
                }
                else if (key.Key == ConsoleKey.Backspace && password.Length > 0)
                {
                    password = password[0..^1];
                    Console.Write("\b \b");
                }
            }
            while (key.Key != ConsoleKey.Enter);
            Console.WriteLine();
            return password;
        }
    }
}