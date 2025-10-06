using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace SecureOTP
{
    /// <summary>
    /// Simplified version for testing the real-time encryption flow
    /// </summary>
    public class SimpleMemoryEncryption : IDisposable
    {
        private readonly Timer _keyRotationTimer;
        private readonly Dictionary<string, EncryptedCommand> _commands;
        private volatile byte[] _currentKey;
        private readonly string _baseKey;
        private int _rotationCounter;
        private readonly object _lockObject = new object();

        public SimpleMemoryEncryption(string baseKey)
        {
            _baseKey = baseKey ?? throw new ArgumentNullException(nameof(baseKey));
            _commands = new Dictionary<string, EncryptedCommand>();
            _currentKey = GenerateKey();
            
            // Rotate keys every 100ms
            _keyRotationTimer = new Timer(RotateKeys, null, 
                TimeSpan.FromMilliseconds(100), 
                TimeSpan.FromMilliseconds(100));
        }

        public void StoreCommandInMemory(byte[] commandBytes, string commandId)
        {
            lock (_lockObject)
            {
                // Encrypt with current key
                var encrypted = EncryptData(commandBytes);
                
                _commands[commandId] = new EncryptedCommand
                {
                    Data = encrypted,
                    CreatedAt = DateTime.UtcNow,
                    AccessCount = 0
                };
            }
        }

        public byte[] RetrieveCommand(string commandId)
        {
            lock (_lockObject)
            {
                if (!_commands.TryGetValue(commandId, out var command))
                {
                    throw new KeyNotFoundException($"Command not found: {commandId}");
                }

                command.AccessCount++;
                return DecryptData(command.Data);
            }
        }

        public void WipeCommand(string commandId)
        {
            lock (_lockObject)
            {
                if (_commands.TryGetValue(commandId, out var command))
                {
                    // Securely wipe
                    RandomNumberGenerator.Fill(command.Data);
                    _commands.Remove(commandId);
                }
            }
        }

        private byte[] EncryptData(byte[] data)
        {
            using var aes = Aes.Create();
            aes.Key = _currentKey;
            aes.GenerateIV();

            using var encryptor = aes.CreateEncryptor();
            var encrypted = encryptor.TransformFinalBlock(data, 0, data.Length);

            // Prepend IV
            var result = new byte[aes.IV.Length + encrypted.Length];
            aes.IV.CopyTo(result, 0);
            encrypted.CopyTo(result, aes.IV.Length);

            return result;
        }

        private byte[] DecryptData(byte[] encryptedData)
        {
            using var aes = Aes.Create();
            aes.Key = _currentKey;

            // Extract IV and data
            var iv = new byte[16]; // AES IV size
            var encrypted = new byte[encryptedData.Length - 16];

            Array.Copy(encryptedData, 0, iv, 0, 16);
            Array.Copy(encryptedData, 16, encrypted, 0, encrypted.Length);

            aes.IV = iv;

            using var decryptor = aes.CreateDecryptor();
            return decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
        }

        private byte[] GenerateKey()
        {
            var input = $"{_baseKey}:{DateTime.UtcNow.Ticks}:{_rotationCounter}";
            return SHA256.HashData(Encoding.UTF8.GetBytes(input));
        }

        private void RotateKeys(object? state)
        {
            lock (_lockObject)
            {
                _rotationCounter++;
                var oldKey = _currentKey;
                _currentKey = GenerateKey();
                
                // Securely wipe old key
                if (oldKey != null)
                {
                    RandomNumberGenerator.Fill(oldKey);
                }
            }
        }

        public void Dispose()
        {
            _keyRotationTimer?.Dispose();
            
            lock (_lockObject)
            {
                // Securely wipe all commands
                foreach (var command in _commands.Values)
                {
                    RandomNumberGenerator.Fill(command.Data);
                }
                _commands.Clear();
                
                // Wipe current key
                if (_currentKey != null)
                {
                    RandomNumberGenerator.Fill(_currentKey);
                }
            }
        }

        private class EncryptedCommand
        {
            public byte[] Data { get; set; } = Array.Empty<byte>();
            public DateTime CreatedAt { get; set; }
            public int AccessCount { get; set; }
        }
    }
}