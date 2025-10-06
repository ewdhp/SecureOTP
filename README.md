# SecureOTP

A robust .NET library for implementing Time-based One-Time Passwords (TOTP) with Google Authenticator compatibility. Features encrypted secret storage, QR code generation, and comprehensive security measures.

[![NuGet Version](https://img.shields.io/nuget/v/SecureOTP)](https://www.nuget.org/packages/SecureOTP)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- 🔐 **Secure Encryption**: AES-256 encryption with PBKDF2 key derivation (100,000 iterations)
- 📱 **Google Authenticator Compatible**: Full RFC 6238 TOTP compliance
- 📊 **QR Code Generation**: Create `otpauth://` URIs for easy phone app setup
- 💾 **Persistent Storage**: Secure file-based storage with atomic operations
- 🛡️ **Security First**: No plain-text secrets ever stored or logged
- 🔄 **Time Window Support**: Configurable time windows for clock skew tolerance
- 📋 **Multi-Account**: Manage multiple TOTP accounts simultaneously
- 🪵 **Logging Integration**: Built-in logging support with Microsoft.Extensions.Logging

## Installation

```bash
dotnet add package SecureOTP
```

## Quick Start

### Basic Usage

```csharp
using SecureOTP;

// Initialize with your master encryption key
var encryptionKey = "your-secure-master-key-here";
var totpManager = new TotpManager(encryptionKey);

// Create a new TOTP account
var result = totpManager.CreateAccount("user@example.com", "MyApp");
Console.WriteLine($"QR Code: {result.QrCodeUri}");

// Generate current code
var codeResult = totpManager.GenerateCode("user@example.com");
Console.WriteLine($"Current code: {codeResult.Code} (expires in {codeResult.RemainingSeconds}s)");

// Verify a code from user's phone
var verification = totpManager.VerifyCode("user@example.com", "123456");
Console.WriteLine($"Valid: {verification.IsValid}");
```

### Advanced Usage with Logging

```csharp
using Microsoft.Extensions.Logging;
using SecureOTP;

// Setup logging
using var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
var logger = loggerFactory.CreateLogger<TotpManager>();

// Initialize with custom storage path and logging
var totpManager = new TotpManager(
    encryptionKey: "your-master-key", 
    storageFilePath: "/secure/path/totp_accounts.json",
    logger: logger
);

// Import existing secret
var importResult = totpManager.ImportAccount(
    accountName: "existing@service.com",
    plainSecret: "JBSWY3DPEHPK3PXP",
    issuer: "ExternalService"
);
```

### Working with Individual Components

```csharp
using SecureOTP;

// Use TotpService directly for basic operations
var totpService = new TotpService("encryption-key");

// Generate and encrypt a new secret
string encryptedSecret = totpService.GenerateNewSecret();

// Generate QR code URI
string qrUri = totpService.GetProvisioningUri(encryptedSecret, "user@example.com", "MyApp");

// Generate current TOTP code
string currentCode = totpService.GenerateCode(encryptedSecret);

// Verify code with 1-step tolerance (30 seconds before/after)
bool isValid = totpService.VerifyCode(encryptedSecret, userEnteredCode, windowSteps: 1);
```

## API Reference

### TotpManager

The main class for complete TOTP account management.

#### Methods

- `CreateAccount(accountName, issuer)` - Create new TOTP account
- `ImportAccount(accountName, plainSecret, issuer, overwrite)` - Import existing secret
- `GenerateCode(accountName)` - Generate current TOTP code
- `VerifyCode(accountName, code, windowSteps)` - Verify TOTP code
- `GetQrCodeUri(accountName, issuer)` - Get QR code URI for existing account
- `RemoveAccount(accountName)` - Remove account
- `ListAccounts()` - List all account names
- `GetAccountsInfo()` - Get detailed account information
- `AccountExists(accountName)` - Check if account exists

### TotpService

Core TOTP operations without persistent storage.

#### Methods

- `GenerateNewSecret()` - Generate new encrypted secret
- `GenerateCode(encryptedSecret)` - Generate TOTP code
- `VerifyCode(encryptedSecret, code, windowSteps)` - Verify TOTP code
- `GetProvisioningUri(encryptedSecret, accountName, issuer)` - Get QR code URI
- `ImportSecret(plainSecret)` - Import and encrypt existing secret
- `GetRemainingTimeForCurrentCode()` - Get seconds until current code expires

### TotpStorage

Persistent storage for encrypted TOTP secrets.

#### Methods

- `StoreAccount(accountName, encryptedSecret)` - Store account
- `GetAccountSecret(accountName)` - Retrieve encrypted secret
- `RemoveAccount(accountName)` - Remove account
- `ListAccounts()` - List account names
- `GetAccountsInfo()` - Get account information
- `AccountExists(accountName)` - Check existence

## Security Features

### Encryption
- **Algorithm**: AES-256-CBC
- **Key Derivation**: PBKDF2 with SHA-256 (100,000 iterations)
- **Salt**: Consistent application salt for key derivation
- **IV**: Random IV for each encryption operation

### Storage Security
- **Atomic Writes**: Temporary file + move for consistency
- **File Permissions**: Restricted to owner only (Unix systems)
- **No Plain Text**: Secrets never stored unencrypted
- **JSON Format**: Structured storage with metadata

### TOTP Compliance
- **Standard**: RFC 6238 Time-Based One-Time Password
- **Algorithm**: HMAC-SHA1 (Google Authenticator compatible)
- **Time Step**: 30 seconds
- **Code Length**: 6 digits
- **Base32 Encoding**: Standard secret encoding

## Configuration

### Encryption Key Management

**Production**: Use a secure, persistent encryption key:

```csharp
// From environment variable
var encryptionKey = Environment.GetEnvironmentVariable("TOTP_MASTER_KEY");

// From configuration
var encryptionKey = configuration["Security:TotpMasterKey"];

// From secure key store
var encryptionKey = await keyVault.GetSecretAsync("totp-master-key");
```

**Development**: Generate a test key:

```csharp
// WARNING: Only for testing!
var totpService = new TotpService(); // Uses auto-generated key
```

### Storage Options

```csharp
// Default: ./totp_accounts.json
var manager = new TotpManager(encryptionKey);

// Custom path
var manager = new TotpManager(encryptionKey, "/secure/path/accounts.json");

// In-memory only (no persistence)
var service = new TotpService(encryptionKey);
```

## Error Handling

The library throws specific exceptions for different error conditions:

```csharp
try
{
    var result = totpManager.CreateAccount("user@example.com");
}
catch (ArgumentException ex)
{
    // Invalid parameters (null/empty account name, etc.)
}
catch (InvalidOperationException ex)
{
    // Business logic errors (account already exists, etc.)
}
catch (Exception ex)
{
    // Unexpected errors (file system, crypto, etc.)
}
```

## Integration Examples

### ASP.NET Core Web API

```csharp
// Startup.cs / Program.cs
builder.Services.AddSingleton<TotpManager>(provider => 
{
    var config = provider.GetRequiredService<IConfiguration>();
    var logger = provider.GetRequiredService<ILogger<TotpManager>>();
    var encryptionKey = config["Security:TotpMasterKey"];
    return new TotpManager(encryptionKey, logger: logger);
});

// Controller
[ApiController]
[Route("api/[controller]")]
public class TotpController : ControllerBase
{
    private readonly TotpManager _totpManager;

    public TotpController(TotpManager totpManager)
    {
        _totpManager = totpManager;
    }

    [HttpPost("setup")]
    public IActionResult SetupTotp([FromBody] SetupRequest request)
    {
        var result = _totpManager.CreateAccount(request.AccountName, "MyApp");
        return Ok(new { qrCodeUri = result.QrCodeUri });
    }

    [HttpPost("verify")]
    public IActionResult VerifyTotp([FromBody] VerifyRequest request)
    {
        var result = _totpManager.VerifyCode(request.AccountName, request.Code);
        return Ok(new { isValid = result.IsValid });
    }
}
```

### Console Application

```csharp
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using SecureOTP;

var host = Host.CreateDefaultBuilder(args)
    .ConfigureServices(services =>
    {
        services.AddSingleton<TotpManager>(provider =>
        {
            var logger = provider.GetService<ILogger<TotpManager>>();
            return new TotpManager("your-encryption-key", logger: logger);
        });
    })
    .Build();

var totpManager = host.Services.GetRequiredService<TotpManager>();

// Your application logic
var result = totpManager.CreateAccount("console-app@example.com");
Console.WriteLine($"Scan this QR code: {result.QrCodeUri}");
```

## Migration from Existing Systems

### From Google Authenticator Export

```csharp
// If you have existing Base32 secrets
var totpManager = new TotpManager("encryption-key");

// Import each account
totpManager.ImportAccount("service1@example.com", "JBSWY3DPEHPK3PXP", "Service1");
totpManager.ImportAccount("service2@example.com", "MFRGG2DFMZTWQ2LK", "Service2");
```

### From Other TOTP Libraries

```csharp
// Extract secrets from your existing system
var existingSecrets = GetExistingTotpSecrets();

var totpManager = new TotpManager("new-encryption-key");

foreach (var (accountName, secret) in existingSecrets)
{
    totpManager.ImportAccount(accountName, secret, "MyApp");
}
```

## Testing

### Unit Testing with Mock Data

```csharp
[Test]
public void VerifyCode_WithValidCode_ReturnsTrue()
{
    // Arrange
    var totpService = new TotpService("test-key");
    var encryptedSecret = totpService.GenerateNewSecret();
    var currentCode = totpService.GenerateCode(encryptedSecret);

    // Act
    var isValid = totpService.VerifyCode(encryptedSecret, currentCode);

    // Assert
    Assert.IsTrue(isValid);
}
```

### Integration Testing

```csharp
[Test]
public void CompleteWorkflow_CreateVerifyRemove_WorksCorrectly()
{
    // Arrange
    var tempPath = Path.GetTempFileName();
    var totpManager = new TotpManager("test-key", tempPath);

    try
    {
        // Act & Assert
        var result = totpManager.CreateAccount("test@example.com");
        Assert.IsTrue(result.Success);

        var codeResult = totpManager.GenerateCode("test@example.com");
        Assert.IsTrue(codeResult.Success);

        var verification = totpManager.VerifyCode("test@example.com", codeResult.Code);
        Assert.IsTrue(verification.IsValid);

        var removed = totpManager.RemoveAccount("test@example.com");
        Assert.IsTrue(removed);
    }
    finally
    {
        File.Delete(tempPath);
    }
}
```

## Performance Considerations

- **Encryption Operations**: ~1-5ms per operation on modern hardware
- **File I/O**: Uses atomic writes with temporary files
- **Memory Usage**: Minimal - secrets cleared after use
- **Concurrent Access**: Thread-safe with file locking

## Troubleshooting

### Common Issues

**Invalid Code Errors**:
- Check system time synchronization
- Verify clock skew tolerance with `windowSteps` parameter
- Ensure secret wasn't corrupted during import

**File Permission Errors**:
- Ensure write permissions to storage directory
- Check file ownership and permissions (Unix systems)

**Encryption Errors**:
- Verify encryption key consistency
- Check for key length requirements (minimum recommended: 32 bytes)

**Import Failures**:
- Validate Base32 secret format
- Remove spaces and ensure proper padding

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to the repository.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security Disclosure

For security-related issues, please email security@ewdhp.dev instead of using the public issue tracker.