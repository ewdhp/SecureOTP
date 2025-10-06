using System;
using System.IO;
using SecureOTP;

namespace SecureOTP.CLI
{
    /// <summary>
    /// Command-line interface for SecureOTP operations
    /// Usage: dotnet run -- [command] [options]
    /// </summary>
    public class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                ShowHelp();
                return;
            }

            try
            {
                var command = args[0].ToLower();
                
                switch (command)
                {
                    case "create":
                        CreateAccount(args);
                        break;
                    case "generate":
                    case "code":
                        GenerateCode(args);
                        break;
                    case "verify":
                        VerifyCode(args);
                        break;
                    case "list":
                        ListAccounts(args);
                        break;
                    case "qr":
                        ShowQRCode(args);
                        break;
                    case "help":
                    case "--help":
                    case "-h":
                        ShowHelp();
                        break;
                    default:
                        Console.WriteLine($"Unknown command: {command}");
                        ShowHelp();
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                Environment.Exit(1);
            }
        }

        private static void CreateAccount(string[] args)
        {
            if (args.Length < 4)
            {
                Console.WriteLine("Usage: create <masterkey> <account> <issuer>");
                return;
            }

            var masterKey = args[1];
            var account = args[2];
            var issuer = args[3];

            var manager = new TotpManager(masterKey);
            var result = manager.CreateAccount(account, issuer);

            if (result.Success)
            {
                Console.WriteLine("Account created successfully!");
                Console.WriteLine($"Account: {account}");
                Console.WriteLine($"QR Code: {result.QrCodeUri}");
            }
            else
            {
                Console.WriteLine($"Failed to create account: {result.Message}");
            }
        }

        private static void GenerateCode(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("Usage: generate <masterkey> <account>");
                return;
            }

            var masterKey = args[1];
            var account = args[2];

            var manager = new TotpManager(masterKey);
            var result = manager.GenerateCode(account);

            if (result.Success)
            {
                Console.WriteLine($"Current code: {result.Code}");
                Console.WriteLine($"Expires in: {result.RemainingSeconds} seconds");
            }
            else
            {
                Console.WriteLine("Failed to generate code");
            }
        }

        private static void VerifyCode(string[] args)
        {
            if (args.Length < 4)
            {
                Console.WriteLine("Usage: verify <masterkey> <account> <code>");
                return;
            }

            var masterKey = args[1];
            var account = args[2];
            var code = args[3];

            var manager = new TotpManager(masterKey);
            var result = manager.VerifyCode(account, code);

            Console.WriteLine($"Code verification: {(result.IsValid ? "VALID" : "INVALID")}");
            if (result.IsValid)
            {
                Console.WriteLine($"Verified at: {result.VerifiedAt:HH:mm:ss}");
            }
        }

        private static void ListAccounts(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: list <masterkey>");
                return;
            }

            var masterKey = args[1];
            var manager = new TotpManager(masterKey);
            var accounts = manager.ListAccounts();

            Console.WriteLine("Stored accounts:");
            foreach (var account in accounts)
            {
                Console.WriteLine($"  • {account}");
            }
        }

        private static void ShowQRCode(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("Usage: qr <masterkey> <account>");
                return;
            }

            var masterKey = args[1];
            var account = args[2];

            var manager = new TotpManager(masterKey);
            var accounts = manager.ListAccounts();
            
            if (accounts.Contains(account))
            {
                // For existing accounts, we need to recreate the QR code
                // This is a limitation - in production you'd store the original URI
                Console.WriteLine($"Account {account} exists but QR code recreation requires the original issuer.");
                Console.WriteLine("Use: create command to generate new accounts with QR codes.");
            }
            else
            {
                Console.WriteLine($"Account {account} not found.");
            }
        }

        private static void ShowHelp()
        {
            Console.WriteLine("SecureOTP Command Line Interface");
            Console.WriteLine("================================");
            Console.WriteLine();
            Console.WriteLine("Commands:");
            Console.WriteLine("  create <masterkey> <account> <issuer>  - Create new TOTP account");
            Console.WriteLine("  generate <masterkey> <account>         - Generate current TOTP code");
            Console.WriteLine("  verify <masterkey> <account> <code>    - Verify a TOTP code");
            Console.WriteLine("  list <masterkey>                       - List all accounts");
            Console.WriteLine("  qr <masterkey> <account>               - Show QR code info");
            Console.WriteLine("  help                                   - Show this help");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  dotnet run -- create mykey user@example.com MyApp");
            Console.WriteLine("  dotnet run -- generate mykey user@example.com");
            Console.WriteLine("  dotnet run -- verify mykey user@example.com 123456");
            Console.WriteLine("  dotnet run -- list mykey");
            Console.WriteLine();
            Console.WriteLine("Note: Replace 'mykey' with your secure master password");
            Console.WriteLine("      All secrets are encrypted with AES-256");
        }
    }
}