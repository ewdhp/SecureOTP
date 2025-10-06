using System;
using System.Threading.Tasks;
using SecureOTP;

namespace SecureOTP.VaultExample
{
    /// <summary>
    /// Practical example of using the Universal Secure Command Vault
    /// Shows real-world integration patterns
    /// </summary>
    class VaultExampleApp
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("🏢 Secure Command Vault - Enterprise Example");
            Console.WriteLine("===========================================\n");

            if (args.Length == 0)
            {
                ShowUsage();
                return;
            }

            var command = args[0].ToLower();

            try
            {
                switch (command)
                {
                    case "setup":
                        await SetupVault();
                        break;
                    case "register":
                        if (args.Length < 3)
                        {
                            Console.WriteLine("Usage: vault register <command-name> <executable-path> [description]");
                            return;
                        }
                        await RegisterCommand(args[1], args[2], args.Length > 3 ? args[3] : "");
                        break;
                    case "login":
                        await LoginToVault();
                        break;
                    case "execute":
                        if (args.Length < 3)
                        {
                            Console.WriteLine("Usage: vault execute <session-id> <command> [args...]");
                            return;
                        }
                        var execArgs = args.Length > 3 ? args[3..] : Array.Empty<string>();
                        await ExecuteCommand(args[1], args[2], execArgs);
                        break;
                    case "list":
                        await ListCommands();
                        break;
                    default:
                        ShowUsage();
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error: {ex.Message}");
            }
        }

        static void ShowUsage()
        {
            Console.WriteLine("📋 Secure Command Vault Usage:");
            Console.WriteLine("==============================");
            Console.WriteLine();
            Console.WriteLine("Commands:");
            Console.WriteLine("  setup                              - Initial vault setup with OTP");
            Console.WriteLine("  register <name> <path> [desc]      - Register executable in vault");
            Console.WriteLine("  login                              - Authenticate with OTP code");
            Console.WriteLine("  execute <session> <cmd> [args]     - Execute vault command");
            Console.WriteLine("  list                               - List available commands");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  vault setup");
            Console.WriteLine("  vault register backup /usr/bin/rsync 'Secure backup tool'");
            Console.WriteLine("  vault register deploy ./deploy.sh 'Production deployment'");
            Console.WriteLine("  vault login");
            Console.WriteLine("  vault execute abc123 backup --dry-run");
            Console.WriteLine();
            Console.WriteLine("Security Features:");
            Console.WriteLine("  🔐 OTP-protected access (Google Authenticator)");
            Console.WriteLine("  🔒 Real-time executable encryption");
            Console.WriteLine("  🚫 No external terminal/SSH access");
            Console.WriteLine("  ⏰ 15-minute session timeout");
            Console.WriteLine("  🧹 Automatic secure cleanup");
        }

        static async Task SetupVault()
        {
            Console.WriteLine("🔐 Setting up Secure Command Vault");
            Console.WriteLine("==================================");

            using var vault = new SecureCommandVault("production-vault-key-2024");
            
            Console.Write("Enter admin email: ");
            var adminEmail = Console.ReadLine() ?? "admin@company.com";
            
            Console.Write("Enter organization name: ");
            var orgName = Console.ReadLine() ?? "MyOrganization";

            var result = await vault.SetupVaultAuthentication(adminEmail, orgName);

            if (result.Success)
            {
                Console.WriteLine("\n✅ Vault setup completed!");
                Console.WriteLine($"📱 QR Code URI: {result.QrCodeUri}");
                Console.WriteLine("\n📋 Next steps:");
                Console.WriteLine("1. Scan QR code with Google Authenticator");
                Console.WriteLine("2. Register commands: vault register <name> <path>");
                Console.WriteLine("3. Login: vault login");
                Console.WriteLine("4. Execute: vault execute <session> <command>");
            }
            else
            {
                Console.WriteLine($"❌ Setup failed: {result.Message}");
            }
        }

        static async Task RegisterCommand(string name, string path, string description)
        {
            Console.WriteLine($"📦 Registering command: {name}");
            Console.WriteLine("==============================");

            if (!File.Exists(path))
            {
                Console.WriteLine($"❌ File not found: {path}");
                return;
            }

            using var vault = new SecureCommandVault("production-vault-key-2024");

            // Define allowed arguments based on command type
            var allowedArgs = GetAllowedArgumentsForCommand(name);

            var result = await vault.RegisterCommand(name, path, description, allowedArgs);

            if (result.Success)
            {
                Console.WriteLine($"✅ Command '{name}' registered successfully");
                Console.WriteLine($"📝 Description: {description}");
                Console.WriteLine($"📍 Original path: {path}");
                Console.WriteLine($"🔒 Now encrypted in secure vault");
                
                if (allowedArgs.Length > 0)
                {
                    Console.WriteLine($"🛡️ Allowed arguments: {string.Join(", ", allowedArgs)}");
                }
            }
            else
            {
                Console.WriteLine($"❌ Registration failed: {result.Message}");
            }
        }

        static async Task LoginToVault()
        {
            Console.WriteLine("🔑 Vault Authentication");
            Console.WriteLine("=======================");

            using var vault = new SecureCommandVault("production-vault-key-2024");

            Console.Write("Enter admin email: ");
            var email = Console.ReadLine() ?? "";

            Console.Write("Enter TOTP code from Google Authenticator: ");
            var totpCode = Console.ReadLine() ?? "";

            var result = await vault.AuthenticateForAccess(email, totpCode);

            if (result.Success)
            {
                Console.WriteLine($"\n✅ Authentication successful!");
                Console.WriteLine($"🎫 Session ID: {result.SessionId}");
                Console.WriteLine($"⏰ Expires: {result.ExpiresAt:yyyy-MM-dd HH:mm:ss}");
                Console.WriteLine($"\n📋 Available Commands ({result.AvailableCommands.Count}):");
                
                foreach (var cmd in result.AvailableCommands)
                {
                    Console.WriteLine($"  • {cmd.Name}: {cmd.Description}");
                    Console.WriteLine($"    Size: {cmd.FileSize} bytes, Registered: {cmd.RegisteredAt:yyyy-MM-dd}");
                }

                Console.WriteLine($"\n💡 Use this session ID to execute commands:");
                Console.WriteLine($"   vault execute {result.SessionId} <command> [args]");
            }
            else
            {
                Console.WriteLine($"❌ Authentication failed: {result.Message}");
            }
        }

        static async Task ExecuteCommand(string sessionId, string command, string[] arguments)
        {
            Console.WriteLine($"⚡ Executing: {command} {string.Join(" ", arguments)}");
            Console.WriteLine("================================================");

            using var vault = new SecureCommandVault("production-vault-key-2024");

            var result = await vault.ExecuteSecureCommand(sessionId, command, arguments);

            if (result.Success)
            {
                Console.WriteLine($"✅ Execution completed");
                Console.WriteLine($"📤 Exit Code: {result.ExitCode}");
                Console.WriteLine($"⏱️ Execution Time: {result.ExecutionTime.TotalMilliseconds:F1}ms");
                
                if (!string.IsNullOrEmpty(result.Output))
                {
                    Console.WriteLine("\n📋 Output:");
                    Console.WriteLine(result.Output);
                }

                if (!string.IsNullOrEmpty(result.ErrorOutput))
                {
                    Console.WriteLine("\n⚠️ Error Output:");
                    Console.WriteLine(result.ErrorOutput);
                }
            }
            else
            {
                Console.WriteLine($"❌ Execution failed: {result.Message}");
            }
        }

        static async Task ListCommands()
        {
            Console.WriteLine("📋 Available Commands in Vault");
            Console.WriteLine("==============================");

            using var vault = new SecureCommandVault("production-vault-key-2024");
            var commands = vault.GetAvailableCommands();

            if (commands.Count == 0)
            {
                Console.WriteLine("No commands registered in vault.");
                Console.WriteLine("Use 'vault register <name> <path>' to add commands.");
                return;
            }

            Console.WriteLine($"Total commands: {commands.Count}\n");

            foreach (var cmd in commands)
            {
                Console.WriteLine($"🔧 {cmd.Name}");
                Console.WriteLine($"   📝 Description: {cmd.Description}");
                Console.WriteLine($"   📊 Size: {cmd.FileSize:N0} bytes");
                Console.WriteLine($"   📅 Registered: {cmd.RegisteredAt:yyyy-MM-dd HH:mm:ss}");
                
                if (cmd.AllowedArguments.Length > 0)
                {
                    Console.WriteLine($"   🛡️ Allowed args: {string.Join(", ", cmd.AllowedArguments)}");
                }
                Console.WriteLine();
            }

            Console.WriteLine("💡 Use 'vault login' to authenticate and execute commands");
        }

        static string[] GetAllowedArgumentsForCommand(string commandName)
        {
            return commandName.ToLower() switch
            {
                "backup" => new[] { "--dry-run", "--verbose", "-v", "/home", "/var/backups" },
                "deploy" => new[] { "staging", "production", "--rollback", "--check" },
                "monitor" => new[] { "--status", "--logs", "--restart", "nginx", "apache" },
                "cleanup" => new[] { "/tmp", "/var/log", "--older-than", "30" },
                "git" => new[] { "status", "pull", "push", "--dry-run", "origin", "main" },
                _ => Array.Empty<string>() // No restrictions for unknown commands
            };
        }
    }
}