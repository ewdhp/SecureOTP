# SecureOTP

A military-grade .NET library for implementing Time-based One-Time Passwords (TOTP) with Google Authenticator compatibility. Features encrypted secret storage, QR code generation, real-time memory encryption, and sandboxed executable proxying.

[![NuGet Version](https://img.shields.io/nuget/v/SecureOTP)](https://www.nuget.org/packages/SecureOTP)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🚀 Features

### Core TOTP Functionality
- 🔐 **AES-256 Encryption**: PBKDF2 key derivation with 100,000 iterations
- 📱 **Google Authenticator Compatible**: Full RFC 6238 TOTP compliance
- 📊 **QR Code Generation**: Create `otpauth://` URIs for easy phone app setup
- 💾 **Persistent Storage**: Secure file-based storage with atomic operations
-  **Time Window Support**: Clock skew tolerance with configurable windows
- 📋 **Multi-Account Management**: Handle multiple TOTP accounts simultaneously

### Advanced Security Features
- 🔒 **Real-Time Memory Encryption**: ChaCha20-Poly1305 with 100ms key rotation
- 🛡️ **Encrypted Executable Proxy**: Store executables encrypted, decrypt only in memory
- 🚫 **Sandboxed Execution**: Prevent external access to encrypted components
- 🧹 **Secure Memory Wiping**: Automatic cleanup with RandomNumberGenerator.Fill()
- 📊 **Forward Secrecy**: Old encryption keys destroyed every 100ms
- 🔍 **Stack Trace Validation**: Prevent unauthorized external execution

## Installation

```bash
dotnet add package SecureOTP
```

## 🚀 Quick Start

### Basic TOTP Usage

```csharp
using SecureOTP;

// Initialize with your master encryption key
var encryptionKey = "your-secure-master-key-here";
var totpManager = new TotpManager(encryptionKey);

// Create a new TOTP account
var result = totpManager.CreateAccount("user@example.com", "MyApp");
if (result.Success)
{
    Console.WriteLine($"📱 QR Code: {result.QrCodeUri}");
    Console.WriteLine("Scan this with Google Authenticator");
}

// Generate current TOTP code
var codeResult = totpManager.GenerateCode("user@example.com");
if (codeResult.Success)
{
    Console.WriteLine($"🔢 Current code: {codeResult.Code}");
    Console.WriteLine($"⏱️ Expires in: {codeResult.RemainingSeconds} seconds");
}

// Verify a code from user's phone
var verification = totpManager.VerifyCode("user@example.com", "123456");
Console.WriteLine($"✅ Valid: {verification.IsValid}");
```

### Real-Time Memory Encryption

```csharp
using SecureOTP;

// Initialize with real-time memory protection
using var memoryVault = new AdvancedMemoryEncryption("memory-key-2024");

// Store sensitive data with multiple encryption layers
var commandId = memoryVault.StoreCommandInMemory(sensitiveData, "my-command");

// Data is now protected with:
// - ChaCha20-Poly1305 encryption per segment  
// - XOR obfuscation with rotating keys
// - Key rotation every 100ms
// - Segmented storage (1KB chunks)

// Retrieve when needed (decrypts temporarily)
var decrypted = memoryVault.RetrieveCommand(commandId);

// Secure cleanup (wipes all traces)
memoryVault.WipeCommand(commandId);
```

### Encrypted Executable Proxy

```csharp
using SecureOTP;

// Initialize encrypted executable manager
using var proxy = new EncryptedExecutableProxy("execution-key-2024");

// One-time setup: encrypt an executable for secure storage
await proxy.EncryptAndStoreExecutable("/usr/bin/google-authenticator", "google-auth");

// Execute through proxy (executable never exposed externally)
var result = await proxy.ProxyGoogleAuthenticator("setup", "user@example.com");
if (result.Success)
{
    Console.WriteLine($"📱 QR URI: {result.QrCodeUri}");
}

var codeResult = await proxy.ProxyGoogleAuthenticator("generate", "user@example.com");
Console.WriteLine($"🔢 Code: {codeResult.Code}");

var verifyResult = await proxy.ProxyGoogleAuthenticator("verify", "user@example.com", "123456");
Console.WriteLine($"✅ Valid: {verifyResult.IsValid}");
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

// Import existing secret with logging
var importResult = totpManager.ImportAccount(
    accountName: "existing@service.com",
    plainSecret: "JBSWY3DPEHPK3PXP",
    issuer: "ExternalService"
);
```

## 🔒 Security Architecture

### Multi-Layer Protection

```
┌─ External Access ─┐    ┌─ Application Layer ─┐    ┌─ Memory Layer ─┐    ┌─ Storage Layer ─┐
│                   │    │                     │    │                │    │                │
│ ❌ Terminal       │    │ ✅ Your App         │    │ 🔒 ChaCha20     │    │ 🔐 AES-256     │
│ ❌ SSH           │ -> │ ✅ Stack Validated   │ -> │ 🔑 Key Rotation  │ -> │ 🔑 PBKDF2      │
│ ❌ Direct Exec   │    │ ✅ Sandboxed        │    │ 🧹 Auto Wipe    │    │ 💾 Atomic I/O  │
│                   │    │                     │    │                │    │                │
└───────────────────┘    └─────────────────────┘    └────────────────┘    └────────────────┘
```

### Key Features

- **🚫 Zero External Access**: Executables cannot be run from terminal/SSH
- **🔒 Real-Time Encryption**: < 1ms plaintext exposure in memory  
- **🔑 Key Rotation**: New encryption keys every 100ms
- **🧹 Secure Wiping**: RandomNumberGenerator.Fill() overwrites
- **📊 Forward Secrecy**: Old keys destroyed automatically
- **🛡️ Stack Validation**: Prevents unauthorized code execution

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

## 📊 Examples & Testing

### Running the Tests

The repository includes two key test examples:

#### 1. Real-Time Memory Encryption Flow Test
```bash
cd StandaloneFlowTest
dotnet run
```
**Demonstrates**: 8KB executable encryption → memory protection → key rotation → secure retrieval

#### 2. Complete TOTP Workflow Test  
```bash
cd StandaloneTotpTest  
dotnet run
```
**Demonstrates**: QR generation → code generation → verification → multi-account → performance

### Test Results Summary
```
🔒 Real-Time Encryption Flow Test
=================================
✅ Plaintext exposure: < 1ms
✅ Memory protection: AES-256 encryption at rest  
✅ Key rotation: Every 100ms with secure wipe
✅ Data integrity: PASSED after encryption/decryption
✅ Automatic cleanup: All memory wiped on disposal

🔒 Complete TOTP Workflow Test  
=============================
✅ QR Code Generation - WORKING (otpauth:// URI)
✅ Code Generation - WORKING (6-digit RFC 6238)
✅ Code Verification - WORKING (with clock skew tolerance)  
✅ Invalid Rejection - WORKING (rejects 123456)
✅ Multi-Account - WORKING (isolated secrets)
✅ Performance - WORKING (0.06ms per operation)
```

## ⚡ Performance Benchmarks

- **TOTP Operations**: ~0.06ms per generate+verify cycle
- **Memory Encryption**: ~1ms for 8KB executable encryption  
- **Key Rotation**: Every 100ms (automatic background)
- **File I/O**: Atomic writes with temporary files
- **Memory Usage**: Minimal - automatic secure cleanup
- **Concurrent Access**: Thread-safe with proper locking

## 🔧 Troubleshooting

### Common Issues

**TOTP Code Issues**:
- ✅ Check system time synchronization (critical for TOTP)
- ✅ Verify clock skew tolerance with time window settings
- ✅ Ensure secret wasn't corrupted during storage/import

**Memory Encryption Issues**:
- ✅ Verify sufficient memory for segmented storage  
- ✅ Check key rotation timer disposal on application shutdown
- ✅ Ensure proper using statements for automatic cleanup

**Executable Proxy Issues**:
- ✅ Verify executable exists before encryption
- ✅ Check file permissions for temp directory creation
- ✅ Ensure stack trace validation allows your calling code

**File Storage Issues**:
- ✅ Ensure write permissions to storage directory
- ✅ Check file ownership and permissions (Unix systems)
- ✅ Verify encryption key consistency across sessions

**Performance Issues**:
- ✅ Use `using` statements for proper disposal
- ✅ Avoid creating multiple instances unnecessarily
- ✅ Monitor memory usage with long-running applications

### Security Validation

**Test Memory Protection**:
```bash
# Run the memory encryption flow test
cd StandaloneFlowTest && dotnet run
# Should show < 1ms plaintext exposure
```

**Test TOTP Workflow**:  
```bash
# Run complete TOTP functionality test
cd StandaloneTotpTest && dotnet run
# Should complete all 8 workflow steps successfully
```

## 📁 Project Structure

```
SecureOTP/
├── 📄 Core Library
│   ├── TotpManager.cs              # High-level TOTP management
│   ├── TotpService.cs              # Core TOTP cryptography  
│   ├── TotpStorage.cs              # Encrypted persistent storage
│   └── SecureOTP.csproj            # Main library project
│
├── 🔒 Advanced Security
│   ├── AdvancedMemoryEncryption.cs # ChaCha20 + key rotation
│   ├── SimpleMemoryEncryption.cs   # Simplified memory protection
│   ├── EncryptedExecutableProxy.cs # Encrypted executable management
│   ├── SandboxedTotpService.cs     # Sandboxed execution model
│   └── InternalTotpAPI.cs          # Internal-only API access
│
├── 🧪 Test Examples
│   ├── StandaloneFlowTest/         # Real-time encryption flow test
│   └── StandaloneTotpTest/         # Complete TOTP workflow test
│
└── 📚 Documentation  
    ├── README.md                   # This comprehensive guide
    ├── LICENSE                     # MIT license
    └── .gitignore                  # Git ignore rules
```

## 🤝 Contributing

Contributions are welcome! This project focuses on:

- 🔐 **Security First**: All changes must maintain or improve security
- ⚡ **Performance**: Keep operations fast (< 1ms for core functions)  
- 📝 **Documentation**: Update README.md for any API changes
- 🧪 **Testing**: Include tests demonstrating new functionality

Please submit pull requests with clear descriptions and test coverage.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔒 Security Disclosure

For security-related issues, please email security@ewdhp.dev instead of using the public issue tracker.

---

**Built with ❤️ for maximum security and performance**