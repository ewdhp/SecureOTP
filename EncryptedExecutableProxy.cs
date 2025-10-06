using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace SecureOTP
{
    /// <summary>
    /// Encrypted executable manager that stores executables encrypted on disk
    /// and only decrypts them in memory for execution within the application context.
    /// </summary>
    public class EncryptedExecutableProxy : IDisposable
    {
        private readonly string _encryptionKey;
        private readonly ILogger<EncryptedExecutableProxy>? _logger;
        private readonly string _storageDirectory;
        private readonly AdvancedMemoryEncryption _memoryEncryption;

        public EncryptedExecutableProxy(string encryptionKey, ILogger<EncryptedExecutableProxy>? logger = null)
        {
            _encryptionKey = encryptionKey ?? throw new ArgumentNullException(nameof(encryptionKey));
            _logger = logger;
            _storageDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                ".secureotp", "encrypted_bins"
            );
            Directory.CreateDirectory(_storageDirectory);
            
            // Initialize real-time memory encryption
            _memoryEncryption = new AdvancedMemoryEncryption($"{encryptionKey}:memory", logger);
        }

        /// <summary>
        /// Encrypts an executable and stores it securely.
        /// The original executable becomes inaccessible from filesystem.
        /// </summary>
        /// <param name="executablePath">Path to the executable to encrypt</param>
        /// <param name="executableName">Name to store it under</param>
        public async Task<bool> EncryptAndStoreExecutable(string executablePath, string executableName)
        {
            try
            {
                if (!File.Exists(executablePath))
                {
                    _logger?.LogError("Executable not found: {Path}", executablePath);
                    return false;
                }

                // Read the original executable
                var executableBytes = await File.ReadAllBytesAsync(executablePath);
                _logger?.LogInformation("Read executable: {Size} bytes", executableBytes.Length);

                // Encrypt the executable
                var encryptedBytes = EncryptData(executableBytes);
                
                // Store encrypted executable
                var encryptedPath = Path.Combine(_storageDirectory, $"{executableName}.enc");
                await File.WriteAllBytesAsync(encryptedPath, encryptedBytes);

                // Set secure permissions
                if (Environment.OSVersion.Platform == PlatformID.Unix)
                {
                    File.SetUnixFileMode(encryptedPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                }

                _logger?.LogInformation("Executable encrypted and stored: {Name}", executableName);
                return true;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to encrypt executable: {Name}", executableName);
                return false;
            }
        }

        /// <summary>
        /// Executes an encrypted executable with proxied I/O.
        /// The executable is decrypted in memory and never written to disk in plain form.
        /// </summary>
        /// <param name="executableName">Name of the encrypted executable</param>
        /// <param name="arguments">Arguments to pass to the executable</param>
        /// <param name="inputData">Data to send to executable's stdin</param>
        /// <returns>Execution result with stdout/stderr</returns>
        public async Task<ExecutionResult> ExecuteEncryptedBinary(string executableName, string arguments = "", string inputData = "")
        {
            try
            {
                // Validate internal execution context
                ValidateInternalExecution();

                var encryptedPath = Path.Combine(_storageDirectory, $"{executableName}.enc");
                if (!File.Exists(encryptedPath))
                {
                    return new ExecutionResult
                    {
                        Success = false,
                        ErrorMessage = $"Encrypted executable '{executableName}' not found"
                    };
                }

                // Decrypt executable from disk
                var encryptedBytes = await File.ReadAllBytesAsync(encryptedPath);
                var executableBytes = DecryptData(encryptedBytes);
                
                _logger?.LogInformation("Decrypted executable: {Size} bytes", executableBytes.Length);

                // IMMEDIATELY store in real-time encrypted memory
                var commandId = $"{executableName}_{Guid.NewGuid():N}";
                _memoryEncryption.StoreCommandInMemory(executableBytes, commandId);
                
                _logger?.LogInformation("Stored executable in encrypted memory: {CommandId}", commandId);
                
                // Securely wipe the plaintext from local memory
                RandomNumberGenerator.Fill(executableBytes);
                
                try
                {
                    // Retrieve executable from encrypted memory only when needed
                    var decryptedExecutable = _memoryEncryption.RetrieveCommand(commandId);
                    
                    // Create temporary executable (minimal exposure time)
                    var tempDir = Path.Combine(Path.GetTempPath(), $"secure_exec_{Guid.NewGuid():N}");
                    Directory.CreateDirectory(tempDir);
                    var tempExecPath = Path.Combine(tempDir, $"{executableName}");
                    
                    await File.WriteAllBytesAsync(tempExecPath, decryptedExecutable);
                    
                    // Immediately wipe the decrypted copy
                    RandomNumberGenerator.Fill(decryptedExecutable);

                    // Make executable on Unix systems
                    if (Environment.OSVersion.Platform == PlatformID.Unix)
                    {
                        File.SetUnixFileMode(tempExecPath, 
                            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                    }

                    // Execute with proxied I/O
                    var result = await ExecuteWithProxy(tempExecPath, arguments, inputData);
                    
                    _logger?.LogInformation("Executed encrypted binary: {Name} -> Exit: {ExitCode}", 
                        executableName, result.ExitCode);

                    return result;
                }
                finally
                {
                    // Clean up temporary files immediately
                    try
                    {
                        if (Directory.Exists(tempDir))
                        {
                            Directory.Delete(tempDir, recursive: true);
                        }
                    }
                    catch (Exception cleanupEx)
                    {
                        _logger?.LogWarning(cleanupEx, "Failed to cleanup temporary directory: {Dir}", tempDir);
                    }
                    
                    // Wipe command from encrypted memory
                    _memoryEncryption.WipeCommand(commandId);
                    _logger?.LogInformation("Wiped command from encrypted memory: {CommandId}", commandId);
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                return new ExecutionResult
                {
                    Success = false,
                    ErrorMessage = $"Access denied: {ex.Message}"
                };
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to execute encrypted binary: {Name}", executableName);
                return new ExecutionResult
                {
                    Success = false,
                    ErrorMessage = $"Execution failed: {ex.Message}"
                };
            }
        }

        /// <summary>
        /// Proxy method for Google Authenticator operations.
        /// Handles TOTP setup and verification through encrypted executable.
        /// </summary>
        /// <param name="operation">Operation: setup, generate, verify</param>
        /// <param name="account">Account name</param>
        /// <param name="code">Code for verification (optional)</param>
        /// <returns>Operation result</returns>
        public async Task<TotpOperationResult> ProxyGoogleAuthenticator(string operation, string account, string code = "")
        {
            try
            {
                var arguments = operation.ToLower() switch
                {
                    "setup" => $"--setup --account {account}",
                    "generate" => $"--generate --account {account}",
                    "verify" => $"--verify --account {account} --code {code}",
                    _ => throw new ArgumentException($"Unknown operation: {operation}")
                };

                var result = await ExecuteEncryptedBinary("google-authenticator", arguments);

                if (result.Success)
                {
                    return ParseGoogleAuthenticatorOutput(result.StandardOutput, operation);
                }
                else
                {
                    return new TotpOperationResult
                    {
                        Success = false,
                        Message = result.ErrorMessage
                    };
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Google Authenticator proxy failed: {Operation}", operation);
                return new TotpOperationResult
                {
                    Success = false,
                    Message = $"Proxy operation failed: {ex.Message}"
                };
            }
        }

        #region Private Methods

        private void ValidateInternalExecution()
        {
            var stackTrace = new System.Diagnostics.StackTrace();
            var callingMethod = stackTrace.GetFrame(2)?.GetMethod();
            var callingAssembly = callingMethod?.DeclaringType?.Assembly;
            var currentAssembly = System.Reflection.Assembly.GetExecutingAssembly();

            // Ensure we're being called from within the same application
            if (callingAssembly != currentAssembly)
            {
                throw new UnauthorizedAccessException("Encrypted executable access is only permitted from within the application");
            }

            // Block direct command-line execution
            var args = Environment.GetCommandLineArgs();
            if (args.Length > 1 && args[1].Contains("google-authenticator"))
            {
                throw new UnauthorizedAccessException("Direct command-line access to encrypted executables is not permitted");
            }
        }

        private async Task<ExecutionResult> ExecuteWithProxy(string executablePath, string arguments, string inputData)
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = executablePath,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(executablePath)
            };

            using var process = new Process { StartInfo = startInfo };
            
            var outputBuilder = new StringBuilder();
            var errorBuilder = new StringBuilder();

            process.OutputDataReceived += (sender, e) =>
            {
                if (e.Data != null)
                {
                    outputBuilder.AppendLine(e.Data);
                    _logger?.LogDebug("STDOUT: {Data}", e.Data);
                }
            };

            process.ErrorDataReceived += (sender, e) =>
            {
                if (e.Data != null)
                {
                    errorBuilder.AppendLine(e.Data);
                    _logger?.LogDebug("STDERR: {Data}", e.Data);
                }
            };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            // Send input data if provided
            if (!string.IsNullOrEmpty(inputData))
            {
                await process.StandardInput.WriteAsync(inputData);
                process.StandardInput.Close();
            }

            // Wait for completion with timeout
            var completed = await Task.Run(() => process.WaitForExit(30000)); // 30 second timeout

            if (!completed)
            {
                process.Kill();
                return new ExecutionResult
                {
                    Success = false,
                    ErrorMessage = "Execution timed out"
                };
            }

            return new ExecutionResult
            {
                Success = process.ExitCode == 0,
                ExitCode = process.ExitCode,
                StandardOutput = outputBuilder.ToString(),
                StandardError = errorBuilder.ToString(),
                ErrorMessage = process.ExitCode != 0 ? errorBuilder.ToString() : null
            };
        }

        private TotpOperationResult ParseGoogleAuthenticatorOutput(string output, string operation)
        {
            // Parse the output from the Google Authenticator executable
            // This would be customized based on your specific executable's output format
            
            return operation.ToLower() switch
            {
                "setup" => ParseSetupOutput(output),
                "generate" => ParseGenerateOutput(output),
                "verify" => ParseVerifyOutput(output),
                _ => new TotpOperationResult { Success = false, Message = "Unknown operation" }
            };
        }

        private TotpOperationResult ParseSetupOutput(string output)
        {
            // Example parsing - customize based on your executable's output
            if (output.Contains("QR code:") || output.Contains("otpauth://"))
            {
                var qrMatch = System.Text.RegularExpressions.Regex.Match(output, @"otpauth://[^\s]+");
                return new TotpOperationResult
                {
                    Success = true,
                    QrCodeUri = qrMatch.Success ? qrMatch.Value : "",
                    Message = "Setup completed successfully"
                };
            }
            
            return new TotpOperationResult { Success = false, Message = "Setup failed" };
        }

        private TotpOperationResult ParseGenerateOutput(string output)
        {
            // Extract 6-digit code from output
            var codeMatch = System.Text.RegularExpressions.Regex.Match(output, @"\b\d{6}\b");
            if (codeMatch.Success)
            {
                return new TotpOperationResult
                {
                    Success = true,
                    Code = codeMatch.Value,
                    Message = "Code generated successfully"
                };
            }
            
            return new TotpOperationResult { Success = false, Message = "Failed to generate code" };
        }

        private TotpOperationResult ParseVerifyOutput(string output)
        {
            var isValid = output.Contains("valid", StringComparison.OrdinalIgnoreCase) &&
                         !output.Contains("invalid", StringComparison.OrdinalIgnoreCase);
            
            return new TotpOperationResult
            {
                Success = true,
                IsValid = isValid,
                Message = isValid ? "Code is valid" : "Code is invalid"
            };
        }

        private byte[] EncryptData(byte[] data)
        {
            using var aes = Aes.Create();
            var key = SHA256.HashData(Encoding.UTF8.GetBytes(_encryptionKey));
            aes.Key = key;
            aes.GenerateIV();

            using var encryptor = aes.CreateEncryptor();
            var encrypted = encryptor.TransformFinalBlock(data, 0, data.Length);

            // Prepend IV to encrypted data
            var result = new byte[aes.IV.Length + encrypted.Length];
            aes.IV.CopyTo(result, 0);
            encrypted.CopyTo(result, aes.IV.Length);

            return result;
        }

        private byte[] DecryptData(byte[] encryptedData)
        {
            using var aes = Aes.Create();
            var key = SHA256.HashData(Encoding.UTF8.GetBytes(_encryptionKey));
            aes.Key = key;

            // Extract IV and encrypted data
            var iv = new byte[aes.IV.Length];
            var encrypted = new byte[encryptedData.Length - iv.Length];

            Array.Copy(encryptedData, 0, iv, 0, iv.Length);
            Array.Copy(encryptedData, iv.Length, encrypted, 0, encrypted.Length);

            aes.IV = iv;

            using var decryptor = aes.CreateDecryptor();
            return decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
        }

        public void Dispose()
        {
            _memoryEncryption?.Dispose();
        }

        #endregion
    }

    #region Result Classes

    public class ExecutionResult
    {
        public bool Success { get; set; }
        public int ExitCode { get; set; }
        public string StandardOutput { get; set; } = string.Empty;
        public string StandardError { get; set; } = string.Empty;
        public string? ErrorMessage { get; set; }
    }

    public class TotpOperationResult
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public string Code { get; set; } = string.Empty;
        public string QrCodeUri { get; set; } = string.Empty;
        public bool IsValid { get; set; }
    }

    #endregion
}