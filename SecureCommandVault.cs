using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace SecureOTP
{
    /// <summary>
    /// Universal Secure Command Vault - OTP-protected access to encrypted executables
    /// Commands are encrypted at execution time and can only run through this program
    /// </summary>
    public class SecureCommandVault : IDisposable
    {
        private readonly TotpManager _totpManager;
        private readonly AdvancedMemoryEncrypt    public class CommandInfo
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public long FileSize { get; set; };
        public DateTime RegisteredAt { get; set; };
        public string[] AllowedArguments { get; set; } = Array.Empty<string>();
    }

    public class DirectoryRegistrationResult
    {
        public bool Success { get; set; }
        public string DirectoryName { get; set; } = string.Empty;
        public int FileCount { get; set; }
        public long TotalSize { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    public class DirectoryExtractionResult
    {
        public bool Success { get; set; }
        public string DirectoryName { get; set; } = string.Empty;
        public string ExtractPath { get; set; } = string.Empty;
        public int ExtractedFiles { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    public class DirectoryInfo
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public long TotalSize { get; set; }
        public int FileCount { get; set; }
        public DateTime RegisteredAt { get; set; }
        public bool PreserveStructure { get; set; }
        public string[] ExcludePatterns { get; set; } = Array.Empty<string>();
    }oryEncryption;
        private readonly ILogger<SecureCommandVault>? _logger;
        private readonly string _vaultStoragePath;
        private readonly Dictionary<string, CommandDefinition> _availableCommands;
        private readonly Dictionary<string, EncryptedDirectory> _encryptedDirectories;
        private readonly Dictionary<string, DateTime> _authorizedSessions;
        private readonly TimeSpan _sessionTimeout = TimeSpan.FromMinutes(15);

        public SecureCommandVault(string encryptionKey, ILogger<SecureCommandVault>? logger = null)
        {
            _totpManager = new TotpManager(encryptionKey, logger: logger);
            _memoryEncryption = new AdvancedMemoryEncryption($"{encryptionKey}:vault");
            _logger = logger;
            
            _vaultStoragePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                ".secureotp", "command_vault.json"
            );
            
            _availableCommands = new Dictionary<string, CommandDefinition>();
            _encryptedDirectories = new Dictionary<string, EncryptedDirectory>();
            _authorizedSessions = new Dictionary<string, DateTime>();
            
            Directory.CreateDirectory(Path.GetDirectoryName(_vaultStoragePath)!);
            LoadCommandVault();
        }

        /// <summary>
        /// Setup OTP authentication for the vault
        /// </summary>
        public async Task<VaultSetupResult> SetupVaultAuthentication(string accountName, string issuer = "SecureCommandVault")
        {
            try
            {
                var setupResult = _totpManager.CreateAccount(accountName, issuer);
                
                if (setupResult.Success)
                {
                    _logger?.LogInformation("Vault OTP setup completed for: {Account}", accountName);
                    
                    return new VaultSetupResult
                    {
                        Success = true,
                        QrCodeUri = setupResult.QrCodeUri,
                        Message = "Scan QR code with Google Authenticator to secure your command vault"
                    };
                }
                
                return new VaultSetupResult
                {
                    Success = false,
                    Message = $"Failed to setup vault authentication: {setupResult.Message}"
                };
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error setting up vault authentication");
                return new VaultSetupResult
                {
                    Success = false,
                    Message = $"Setup error: {ex.Message}"
                };
            }
        }

        /// <summary>
        /// Authenticate and create a session for command access
        /// </summary>
        public async Task<AuthenticationResult> AuthenticateForAccess(string accountName, string totpCode)
        {
            try
            {
                var verification = _totpManager.VerifyCode(accountName, totpCode);
                
                if (verification.IsValid)
                {
                    var sessionId = GenerateSessionId();
                    _authorizedSessions[sessionId] = DateTime.UtcNow;
                    
                    _logger?.LogInformation("Successful authentication for vault access: {Account}", accountName);
                    
                    return new AuthenticationResult
                    {
                        Success = true,
                        SessionId = sessionId,
                        ExpiresAt = DateTime.UtcNow.Add(_sessionTimeout),
                        AvailableCommands = GetAvailableCommandsList(),
                        Message = "Authentication successful. Access granted to command vault."
                    };
                }
                
                _logger?.LogWarning("Failed authentication attempt for: {Account}", accountName);
                return new AuthenticationResult
                {
                    Success = false,
                    Message = "Invalid TOTP code. Access denied."
                };
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Authentication error");
                return new AuthenticationResult
                {
                    Success = false,
                    Message = $"Authentication error: {ex.Message}"
                };
            }
        }

        /// <summary>
        /// Add a command to the secure vault
        /// </summary>
        public async Task<CommandRegistrationResult> RegisterCommand(
            string commandName, 
            string executablePath, 
            string description = "",
            string[]? allowedArguments = null)
        {
            try
            {
                if (!File.Exists(executablePath))
                {
                    return new CommandRegistrationResult
                    {
                        Success = false,
                        Message = $"Executable not found: {executablePath}"
                    };
                }

                // Read and encrypt the executable
                var executableBytes = await File.ReadAllBytesAsync(executablePath);
                var commandId = $"cmd_{commandName}_{Guid.NewGuid():N}";
                
                // Store in encrypted memory
                _memoryEncryption.StoreCommandInMemory(executableBytes, commandId);
                
                // Create command definition
                var commandDef = new CommandDefinition
                {
                    Name = commandName,
                    Description = description,
                    OriginalPath = executablePath,
                    EncryptedCommandId = commandId,
                    AllowedArguments = allowedArguments ?? Array.Empty<string>(),
                    RegisteredAt = DateTime.UtcNow,
                    FileSize = executableBytes.Length,
                    FileHash = Convert.ToBase64String(SHA256.HashData(executableBytes))
                };

                _availableCommands[commandName] = commandDef;
                
                // Secure wipe the original if requested
                await SecureWipeOriginalFile(executablePath);
                
                // Save vault configuration
                await SaveCommandVault();
                
                _logger?.LogInformation("Command registered: {Command} ({Size} bytes)", 
                    commandName, executableBytes.Length);

                return new CommandRegistrationResult
                {
                    Success = true,
                    CommandName = commandName,
                    Message = $"Command '{commandName}' successfully registered and encrypted in vault"
                };
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error registering command: {Command}", commandName);
                return new CommandRegistrationResult
                {
                    Success = false,
                    Message = $"Registration error: {ex.Message}"
                };
            }
        }

        /// <summary>
        /// Encrypt and register a directory in the secure vault
        /// </summary>
        public async Task<DirectoryRegistrationResult> RegisterSecureDirectory(
            string sessionId,
            string directoryPath,
            string directoryName,
            string description = "",
            bool preserveStructure = true,
            string[]? excludePatterns = null)
        {
            try
            {
                // Validate session
                if (!IsSessionValid(sessionId))
                {
                    return new DirectoryRegistrationResult
                    {
                        Success = false,
                        Message = "Invalid or expired session. Please authenticate again."
                    };
                }

                // Validate directory exists
                if (!Directory.Exists(directoryPath))
                {
                    return new DirectoryRegistrationResult
                    {
                        Success = false,
                        Message = $"Directory not found: {directoryPath}"
                    };
                }

                // Check if directory name already exists
                if (_encryptedDirectories.ContainsKey(directoryName))
                {
                    return new DirectoryRegistrationResult
                    {
                        Success = false,
                        Message = $"Directory '{directoryName}' already exists in vault"
                    };
                }

                _logger?.LogInformation("Starting directory encryption: {Directory}", directoryPath);

                // Create encrypted directory archive
                var directoryId = Guid.NewGuid().ToString("N");
                var encryptedData = await CreateEncryptedDirectoryArchive(directoryPath, excludePatterns, preserveStructure);
                
                // Store in encrypted memory
                _memoryEncryption.StoreCommandInMemory(encryptedData, directoryId);
                
                // Create directory definition
                var directoryDef = new EncryptedDirectory
                {
                    Name = directoryName,
                    Description = description,
                    OriginalPath = directoryPath,
                    EncryptedDirectoryId = directoryId,
                    PreserveStructure = preserveStructure,
                    ExcludePatterns = excludePatterns ?? Array.Empty<string>(),
                    RegisteredAt = DateTime.UtcNow,
                    TotalSize = encryptedData.Length,
                    FileCount = CountFilesInDirectory(directoryPath, excludePatterns),
                    DirectoryHash = Convert.ToBase64String(SHA256.HashData(encryptedData))
                };

                _encryptedDirectories[directoryName] = directoryDef;
                
                // Optionally secure wipe the original directory
                // await SecureWipeOriginalDirectory(directoryPath);
                
                // Save vault configuration
                await SaveCommandVault();
                
                _logger?.LogInformation("Directory registered: {Directory} ({Size} bytes, {FileCount} files)", 
                    directoryName, encryptedData.Length, directoryDef.FileCount);

                return new DirectoryRegistrationResult
                {
                    Success = true,
                    DirectoryName = directoryName,
                    FileCount = directoryDef.FileCount,
                    TotalSize = directoryDef.TotalSize,
                    Message = $"Directory '{directoryName}' successfully encrypted and stored in vault"
                };
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error registering directory: {Directory}", directoryName);
                return new DirectoryRegistrationResult
                {
                    Success = false,
                    Message = $"Registration error: {ex.Message}"
                };
            }
        }

        /// <summary>
        /// Extract an encrypted directory from the vault
        /// </summary>
        public async Task<DirectoryExtractionResult> ExtractSecureDirectory(
            string sessionId,
            string directoryName,
            string extractPath,
            bool overwriteExisting = false)
        {
            try
            {
                // Validate session
                if (!IsSessionValid(sessionId))
                {
                    return new DirectoryExtractionResult
                    {
                        Success = false,
                        Message = "Invalid or expired session. Please authenticate again."
                    };
                }

                // Check if directory exists in vault
                if (!_encryptedDirectories.TryGetValue(directoryName, out var directoryDef))
                {
                    return new DirectoryExtractionResult
                    {
                        Success = false,
                        Message = $"Directory '{directoryName}' not found in vault."
                    };
                }

                // Validate extraction path
                if (Directory.Exists(extractPath) && !overwriteExisting)
                {
                    return new DirectoryExtractionResult
                    {
                        Success = false,
                        Message = $"Extraction path already exists: {extractPath}. Use overwriteExisting=true to replace."
                    };
                }

                // Retrieve encrypted directory data
                var encryptedData = _memoryEncryption.RetrieveCommand(directoryDef.EncryptedDirectoryId);
                
                // Extract directory from encrypted archive
                var extractedFiles = await ExtractEncryptedDirectoryArchive(encryptedData, extractPath, directoryDef.PreserveStructure);

                _logger?.LogInformation("Directory extracted: {Directory} -> {ExtractPath} ({FileCount} files)", 
                    directoryName, extractPath, extractedFiles);

                // Update session activity
                _authorizedSessions[sessionId] = DateTime.UtcNow;

                return new DirectoryExtractionResult
                {
                    Success = true,
                    DirectoryName = directoryName,
                    ExtractPath = extractPath,
                    ExtractedFiles = extractedFiles,
                    Message = $"Directory '{directoryName}' successfully extracted to {extractPath}"
                };
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error extracting directory: {Directory}", directoryName);
                return new DirectoryExtractionResult
                {
                    Success = false,
                    Message = $"Extraction error: {ex.Message}"
                };
            }
        }

        /// <summary>
        /// List all encrypted directories in the vault
        /// </summary>
        public List<DirectoryInfo> GetEncryptedDirectories(string sessionId)
        {
            if (!IsSessionValid(sessionId))
            {
                return new List<DirectoryInfo>();
            }

            var directories = new List<DirectoryInfo>();
            
            foreach (var kvp in _encryptedDirectories)
            {
                directories.Add(new DirectoryInfo
                {
                    Name = kvp.Value.Name,
                    Description = kvp.Value.Description,
                    TotalSize = kvp.Value.TotalSize,
                    FileCount = kvp.Value.FileCount,
                    RegisteredAt = kvp.Value.RegisteredAt,
                    PreserveStructure = kvp.Value.PreserveStructure,
                    ExcludePatterns = kvp.Value.ExcludePatterns
                });
            }

            return directories;
        }

        /// <summary>
        /// Remove an encrypted directory from the vault
        /// </summary>
        public async Task<bool> RemoveEncryptedDirectory(string sessionId, string directoryName)
        {
            if (!IsSessionValid(sessionId))
                return false;

            if (_encryptedDirectories.TryGetValue(directoryName, out var directoryDef))
            {
                // Wipe from memory
                _memoryEncryption.WipeCommand(directoryDef.EncryptedDirectoryId);
                
                // Remove from vault
                _encryptedDirectories.Remove(directoryName);
                
                // Save updated vault
                await SaveCommandVault();
                
                _logger?.LogInformation("Directory removed from vault: {Directory}", directoryName);
                return true;
            }

            return false;
        }

        /// <summary>
        /// Execute a command from the secure vault (requires valid session)
        /// </summary>
        public async Task<CommandExecutionResult> ExecuteSecureCommand(
            string sessionId, 
            string commandName, 
            string[]? arguments = null, 
            string? inputData = null)
        {
            try
            {
                // Validate session
                if (!IsSessionValid(sessionId))
                {
                    return new CommandExecutionResult
                    {
                        Success = false,
                        Message = "Invalid or expired session. Please authenticate again."
                    };
                }

                // Check if command exists
                if (!_availableCommands.TryGetValue(commandName, out var commandDef))
                {
                    return new CommandExecutionResult
                    {
                        Success = false,
                        Message = $"Command '{commandName}' not found in vault."
                    };
                }

                // Validate arguments if restrictions exist
                if (commandDef.AllowedArguments.Length > 0 && arguments != null)
                {
                    foreach (var arg in arguments)
                    {
                        if (!IsArgumentAllowed(arg, commandDef.AllowedArguments))
                        {
                            return new CommandExecutionResult
                            {
                                Success = false,
                                Message = $"Argument '{arg}' not allowed for command '{commandName}'"
                            };
                        }
                    }
                }

                // Retrieve encrypted executable
                var executableBytes = _memoryEncryption.RetrieveCommand(commandDef.EncryptedCommandId);
                
                // Create temporary execution environment
                var tempDir = Path.Combine(Path.GetTempPath(), $"secure_cmd_{Guid.NewGuid():N}");
                Directory.CreateDirectory(tempDir);

                try
                {
                    var tempExecPath = Path.Combine(tempDir, $"{commandName}");
                    await File.WriteAllBytesAsync(tempExecPath, executableBytes);

                    // Set executable permissions on Unix
                    if (Environment.OSVersion.Platform == PlatformID.Unix)
                    {
                        File.SetUnixFileMode(tempExecPath, 
                            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                    }

                    // Execute with security controls
                    var result = await ExecuteWithSecurity(tempExecPath, arguments, inputData, commandName);

                    _logger?.LogInformation("Command executed: {Command} -> Exit: {ExitCode}", 
                        commandName, result.ExitCode);

                    // Update session activity
                    _authorizedSessions[sessionId] = DateTime.UtcNow;

                    return result;
                }
                finally
                {
                    // Secure cleanup
                    try
                    {
                        if (Directory.Exists(tempDir))
                        {
                            // Secure wipe temporary files
                            foreach (var file in Directory.GetFiles(tempDir))
                            {
                                await SecureWipeFile(file);
                            }
                            Directory.Delete(tempDir, recursive: true);
                        }
                    }
                    catch (Exception cleanupEx)
                    {
                        _logger?.LogWarning(cleanupEx, "Failed to cleanup temporary directory: {Dir}", tempDir);
                    }

                    // Secure wipe decrypted executable from memory
                    RandomNumberGenerator.Fill(executableBytes);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Error executing command: {Command}", commandName);
                return new CommandExecutionResult
                {
                    Success = false,
                    Message = $"Execution error: {ex.Message}"
                };
            }
        }

        /// <summary>
        /// List all available commands in the vault
        /// </summary>
        public List<CommandInfo> GetAvailableCommands(string sessionId = null)
        {
            if (sessionId != null && !IsSessionValid(sessionId))
            {
                return new List<CommandInfo>();
            }

            return GetAvailableCommandsList();
        }

        /// <summary>
        /// Remove a command from the vault
        /// </summary>
        public async Task<bool> RemoveCommand(string sessionId, string commandName)
        {
            if (!IsSessionValid(sessionId))
                return false;

            if (_availableCommands.TryGetValue(commandName, out var commandDef))
            {
                // Wipe from memory
                _memoryEncryption.WipeCommand(commandDef.EncryptedCommandId);
                
                // Remove from vault
                _availableCommands.Remove(commandName);
                
                // Save updated vault
                await SaveCommandVault();
                
                _logger?.LogInformation("Command removed from vault: {Command}", commandName);
                return true;
            }

            return false;
        }

        private async Task<CommandExecutionResult> ExecuteWithSecurity(
            string executablePath, 
            string[]? arguments, 
            string? inputData, 
            string commandName)
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = executablePath,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    RedirectStandardInput = !string.IsNullOrEmpty(inputData),
                    CreateNoWindow = true,
                    WorkingDirectory = Path.GetTempPath()
                }
            };

            if (arguments != null && arguments.Length > 0)
            {
                foreach (var arg in arguments)
                {
                    process.StartInfo.ArgumentList.Add(arg);
                }
            }

            var output = new StringBuilder();
            var errors = new StringBuilder();
            var startTime = DateTime.UtcNow;

            process.OutputDataReceived += (sender, e) => {
                if (!string.IsNullOrEmpty(e.Data))
                    output.AppendLine(e.Data);
            };

            process.ErrorDataReceived += (sender, e) => {
                if (!string.IsNullOrEmpty(e.Data))
                    errors.AppendLine(e.Data);
            };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            if (!string.IsNullOrEmpty(inputData))
            {
                await process.StandardInput.WriteAsync(inputData);
                process.StandardInput.Close();
            }

            // Wait with timeout (5 minutes max)
            var completed = process.WaitForExit(300000);
            
            if (!completed)
            {
                process.Kill(entireProcessTree: true);
                return new CommandExecutionResult
                {
                    Success = false,
                    Message = "Command execution timed out (5 minutes)"
                };
            }

            var duration = DateTime.UtcNow - startTime;

            return new CommandExecutionResult
            {
                Success = process.ExitCode == 0,
                ExitCode = process.ExitCode,
                Output = output.ToString(),
                ErrorOutput = errors.ToString(),
                ExecutionTime = duration,
                CommandName = commandName,
                Message = process.ExitCode == 0 ? "Command executed successfully" : $"Command failed with exit code {process.ExitCode}"
            };
        }

        private bool IsSessionValid(string sessionId)
        {
            if (string.IsNullOrEmpty(sessionId) || !_authorizedSessions.ContainsKey(sessionId))
                return false;

            var sessionTime = _authorizedSessions[sessionId];
            if (DateTime.UtcNow - sessionTime > _sessionTimeout)
            {
                _authorizedSessions.Remove(sessionId);
                return false;
            }

            return true;
        }

        private bool IsArgumentAllowed(string argument, string[] allowedArguments)
        {
            foreach (var allowed in allowedArguments)
            {
                if (argument.Equals(allowed, StringComparison.OrdinalIgnoreCase) ||
                    argument.StartsWith(allowed, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            return false;
        }

        private List<CommandInfo> GetAvailableCommandsList()
        {
            var commands = new List<CommandInfo>();
            
            foreach (var kvp in _availableCommands)
            {
                commands.Add(new CommandInfo
                {
                    Name = kvp.Value.Name,
                    Description = kvp.Value.Description,
                    FileSize = kvp.Value.FileSize,
                    RegisteredAt = kvp.Value.RegisteredAt,
                    AllowedArguments = kvp.Value.AllowedArguments
                });
            }

            return commands;
        }

        private string GenerateSessionId()
        {
            var bytes = new byte[32];
            RandomNumberGenerator.Fill(bytes);
            return Convert.ToBase64String(bytes).Replace("+", "").Replace("/", "").Replace("=", "")[..16];
        }

        private async Task LoadCommandVault()
        {
            if (!File.Exists(_vaultStoragePath))
                return;

            try
            {
                var json = await File.ReadAllTextAsync(_vaultStoragePath);
                var vault = JsonSerializer.Deserialize<VaultStorage>(json);
                
                if (vault?.Commands != null)
                {
                    foreach (var cmd in vault.Commands)
                    {
                        _availableCommands[cmd.Name] = cmd;
                    }
                }
                
                if (vault?.Directories != null)
                {
                    foreach (var dir in vault.Directories)
                    {
                        _encryptedDirectories[dir.Name] = dir;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Failed to load command vault");
            }
        }

        private async Task SaveCommandVault()
        {
            try
            {
                var vault = new VaultStorage
                {
                    Commands = _availableCommands.Values.ToArray(),
                    Directories = _encryptedDirectories.Values.ToArray(),
                    LastUpdated = DateTime.UtcNow
                };

                var json = JsonSerializer.Serialize(vault, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(_vaultStoragePath, json);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to save command vault");
            }
        }

        private async Task SecureWipeFile(string filePath)
        {
            try
            {
                if (File.Exists(filePath))
                {
                    var fileInfo = new FileInfo(filePath);
                    var length = fileInfo.Length;
                    
                    using (var stream = File.OpenWrite(filePath))
                    {
                        var buffer = new byte[4096];
                        for (long pos = 0; pos < length; pos += buffer.Length)
                        {
                            RandomNumberGenerator.Fill(buffer);
                            await stream.WriteAsync(buffer, 0, (int)Math.Min(buffer.Length, length - pos));
                        }
                        await stream.FlushAsync();
                    }
                    
                    File.Delete(filePath);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogWarning(ex, "Failed to secure wipe file: {File}", filePath);
            }
        }

        private async Task SecureWipeOriginalFile(string filePath)
        {
            // Ask user or implement policy for wiping originals
            _logger?.LogInformation("Original file preserved: {File}", filePath);
            // In production, you might want to:
            // await SecureWipeFile(filePath);
        }

        private async Task<byte[]> CreateEncryptedDirectoryArchive(string directoryPath, string[]? excludePatterns, bool preserveStructure)
        {
            using var memoryStream = new MemoryStream();
            using var writer = new BinaryWriter(memoryStream);

            // Write header information
            writer.Write("SECDIR_V1"); // Magic number and version
            writer.Write(preserveStructure);
            writer.Write(excludePatterns?.Length ?? 0);
            
            if (excludePatterns != null)
            {
                foreach (var pattern in excludePatterns)
                {
                    writer.Write(pattern);
                }
            }

            // Get all files in directory
            var files = Directory.GetFiles(directoryPath, "*", SearchOption.AllDirectories)
                .Where(f => !IsExcluded(f, excludePatterns))
                .ToArray();

            writer.Write(files.Length);

            foreach (var filePath in files)
            {
                var relativePath = Path.GetRelativePath(directoryPath, filePath);
                var fileData = await File.ReadAllBytesAsync(filePath);
                var fileInfo = new FileInfo(filePath);

                // Write file metadata
                writer.Write(relativePath);
                writer.Write(fileInfo.CreationTimeUtc.ToBinary());
                writer.Write(fileInfo.LastWriteTimeUtc.ToBinary());
                writer.Write((int)fileInfo.Attributes);
                writer.Write(fileData.Length);
                
                // Write file data
                writer.Write(fileData);
            }

            return memoryStream.ToArray();
        }

        private async Task<int> ExtractEncryptedDirectoryArchive(byte[] encryptedData, string extractPath, bool preserveStructure)
        {
            using var memoryStream = new MemoryStream(encryptedData);
            using var reader = new BinaryReader(memoryStream);

            // Read and verify header
            var magic = reader.ReadString();
            if (magic != "SECDIR_V1")
            {
                throw new InvalidDataException("Invalid directory archive format");
            }

            var archivePreserveStructure = reader.ReadBoolean();
            var excludePatternsCount = reader.ReadInt32();
            
            // Skip exclude patterns (they're for reference only during extraction)
            for (int i = 0; i < excludePatternsCount; i++)
            {
                reader.ReadString();
            }

            var fileCount = reader.ReadInt32();
            var extractedFiles = 0;

            // Create extraction directory
            Directory.CreateDirectory(extractPath);

            for (int i = 0; i < fileCount; i++)
            {
                var relativePath = reader.ReadString();
                var creationTime = DateTime.FromBinary(reader.ReadInt64());
                var lastWriteTime = DateTime.FromBinary(reader.ReadInt64());
                var attributes = (FileAttributes)reader.ReadInt32();
                var fileSize = reader.ReadInt32();
                var fileData = reader.ReadBytes(fileSize);

                // Determine target path
                var targetPath = preserveStructure && archivePreserveStructure
                    ? Path.Combine(extractPath, relativePath)
                    : Path.Combine(extractPath, Path.GetFileName(relativePath));

                // Create directory if needed
                var targetDir = Path.GetDirectoryName(targetPath)!;
                Directory.CreateDirectory(targetDir);

                // Write file
                await File.WriteAllBytesAsync(targetPath, fileData);

                // Restore file metadata
                var fileInfo = new FileInfo(targetPath);
                fileInfo.CreationTimeUtc = creationTime;
                fileInfo.LastWriteTimeUtc = lastWriteTime;
                fileInfo.Attributes = attributes;

                extractedFiles++;
            }

            return extractedFiles;
        }

        private bool IsExcluded(string filePath, string[]? excludePatterns)
        {
            if (excludePatterns == null || excludePatterns.Length == 0)
                return false;

            var fileName = Path.GetFileName(filePath);
            var relativePath = filePath;

            foreach (var pattern in excludePatterns)
            {
                if (fileName.Contains(pattern, StringComparison.OrdinalIgnoreCase) ||
                    relativePath.Contains(pattern, StringComparison.OrdinalIgnoreCase) ||
                    System.Text.RegularExpressions.Regex.IsMatch(fileName, pattern.Replace("*", ".*"), 
                        System.Text.RegularExpressions.RegexOptions.IgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private int CountFilesInDirectory(string directoryPath, string[]? excludePatterns)
        {
            try
            {
                return Directory.GetFiles(directoryPath, "*", SearchOption.AllDirectories)
                    .Count(f => !IsExcluded(f, excludePatterns));
            }
            catch
            {
                return 0;
            }
        }

        private async Task SecureWipeOriginalDirectory(string directoryPath)
        {
            // Implementation for securely wiping original directory
            // This would recursively wipe all files and then remove the directory
            _logger?.LogInformation("Original directory preserved: {Directory}", directoryPath);
            // In production:
            // foreach (var file in Directory.GetFiles(directoryPath, "*", SearchOption.AllDirectories))
            // {
            //     await SecureWipeFile(file);
            // }
            // Directory.Delete(directoryPath, true);
        }

        public void Dispose()
        {
            _totpManager?.Dispose();
            _memoryEncryption?.Dispose();
            
            // Clear all sessions
            _authorizedSessions.Clear();
            _encryptedDirectories.Clear();
        }
    }

    #region Data Classes

    public class CommandDefinition
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string OriginalPath { get; set; } = string.Empty;
        public string EncryptedCommandId { get; set; } = string.Empty;
        public string[] AllowedArguments { get; set; } = Array.Empty<string>();
        public DateTime RegisteredAt { get; set; }
        public long FileSize { get; set; }
        public string FileHash { get; set; } = string.Empty;
    }

    public class EncryptedDirectory
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string OriginalPath { get; set; } = string.Empty;
        public string EncryptedDirectoryId { get; set; } = string.Empty;
        public bool PreserveStructure { get; set; } = true;
        public string[] ExcludePatterns { get; set; } = Array.Empty<string>();
        public DateTime RegisteredAt { get; set; }
        public long TotalSize { get; set; }
        public int FileCount { get; set; }
        public string DirectoryHash { get; set; } = string.Empty;
    }

    public class VaultStorage
    {
        public CommandDefinition[] Commands { get; set; } = Array.Empty<CommandDefinition>();
        public EncryptedDirectory[] Directories { get; set; } = Array.Empty<EncryptedDirectory>();
        public DateTime LastUpdated { get; set; }
    }

    public class VaultSetupResult
    {
        public bool Success { get; set; }
        public string QrCodeUri { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
    }

    public class AuthenticationResult
    {
        public bool Success { get; set; }
        public string SessionId { get; set; } = string.Empty;
        public DateTime ExpiresAt { get; set; }
        public List<CommandInfo> AvailableCommands { get; set; } = new();
        public string Message { get; set; } = string.Empty;
    }

    public class CommandRegistrationResult
    {
        public bool Success { get; set; }
        public string CommandName { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
    }

    public class CommandExecutionResult
    {
        public bool Success { get; set; }
        public int ExitCode { get; set; }
        public string Output { get; set; } = string.Empty;
        public string ErrorOutput { get; set; } = string.Empty;
        public TimeSpan ExecutionTime { get; set; }
        public string CommandName { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
    }

    public class CommandInfo
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public long FileSize { get; set; }
        public DateTime RegisteredAt { get; set; }
        public string[] AllowedArguments { get; set; } = Array.Empty<string>();
    }

    #endregion
}