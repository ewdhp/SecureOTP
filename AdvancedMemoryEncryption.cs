using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecureOTP
{
    /// <summary>
    /// Advanced in-memory encryption manager for protecting decrypted commands
    /// Uses multiple algorithms: ChaCha20-Poly1305, RC4-Drop, XOR obfuscation, and polymorphic keys
    /// </summary>
    public class AdvancedMemoryEncryption : IDisposable
    {
        private readonly Timer _keyRotationTimer;
        private readonly Dictionary<string, MemoryCommand> _commands;
        private volatile byte[] _currentPolymorphicKey;
        private readonly string _baseKey;
        private int _rotationCounter;
        private readonly object _lockObject = new object();

        public AdvancedMemoryEncryption(string baseKey)
        {
            _baseKey = baseKey ?? throw new ArgumentNullException(nameof(baseKey));
            _commands = new Dictionary<string, MemoryCommand>();
            _currentPolymorphicKey = GeneratePolymorphicKey();
            
            // Rotate keys every 100ms for maximum security
            _keyRotationTimer = new Timer(RotateKeys, null, TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(100));
        }

        /// <summary>
        /// Stores command in memory using multiple encryption layers
        /// </summary>
        public string StoreCommandInMemory(byte[] commandBytes, string commandId)
        {
            lock (_lockObject)
            {
                // Layer 1: Segment the command
                var segments = SegmentCommand(commandBytes);
                
                // Layer 2: Apply ChaCha20-Poly1305 to each segment
                var encryptedSegments = new List<EncryptedSegment>();
                foreach (var segment in segments)
                {
                    var nonce = RandomNumberGenerator.GetBytes(12); // ChaCha20 nonce size
                    var segmentKey = DeriveSegmentKey(segment.Position);
                    var encrypted = EncryptWithChaCha20(segment.Data, segmentKey, nonce);
                    
                    encryptedSegments.Add(new EncryptedSegment
                    {
                        Data = encrypted,
                        Nonce = nonce,
                        Position = segment.Position,
                        Size = segment.Data.Length
                    });
                }

                // Layer 3: Apply XOR obfuscation to metadata
                var obfuscatedMetadata = ObfuscateMetadata(encryptedSegments);

                var memoryCommand = new MemoryCommand
                {
                    Segments = encryptedSegments,
                    ObfuscatedMetadata = obfuscatedMetadata,
                    CreatedAt = DateTime.UtcNow,
                    AccessCount = 0
                };

                _commands[commandId] = memoryCommand;
                return commandId;
            }
        }

        /// <summary>
        /// Retrieves and decrypts command from memory
        /// </summary>
        public byte[] RetrieveCommand(string commandId)
        {
            lock (_lockObject)
            {
                if (!_commands.TryGetValue(commandId, out var memoryCommand))
                {
                    throw new KeyNotFoundException($"Command not found: {commandId}");
                }

                memoryCommand.AccessCount++;

                // Reconstruct original command
                var totalSize = 0;
                var decryptedSegments = new List<CommandSegment>();

                foreach (var segment in memoryCommand.Segments)
                {
                    var segmentKey = DeriveSegmentKey(segment.Position);
                    var decrypted = DecryptWithChaCha20(segment.Data, segmentKey, segment.Nonce);
                    
                    decryptedSegments.Add(new CommandSegment
                    {
                        Data = decrypted,
                        Position = segment.Position
                    });
                    
                    totalSize += decrypted.Length;
                }

                // Sort segments by position and reconstruct
                decryptedSegments.Sort((a, b) => a.Position.CompareTo(b.Position));
                
                var result = new byte[totalSize];
                var offset = 0;
                
                foreach (var segment in decryptedSegments)
                {
                    segment.Data.CopyTo(result, offset);
                    offset += segment.Data.Length;
                }

                return result;
            }
        }

        /// <summary>
        /// Removes command from memory and securely wipes
        /// </summary>
        public void WipeCommand(string commandId)
        {
            lock (_lockObject)
            {
                if (_commands.TryGetValue(commandId, out var command))
                {
                    // Securely wipe all segments
                    foreach (var segment in command.Segments)
                    {
                        RandomNumberGenerator.Fill(segment.Data);
                        RandomNumberGenerator.Fill(segment.Nonce);
                    }
                    
                    RandomNumberGenerator.Fill(command.ObfuscatedMetadata);
                    _commands.Remove(commandId);
                }
            }
        }

        private List<CommandSegment> SegmentCommand(byte[] data)
        {
            const int segmentSize = 1024; // 1KB segments
            var segments = new List<CommandSegment>();
            
            for (int i = 0; i < data.Length; i += segmentSize)
            {
                var length = Math.Min(segmentSize, data.Length - i);
                var segmentData = new byte[length];
                Array.Copy(data, i, segmentData, 0, length);
                
                segments.Add(new CommandSegment
                {
                    Data = segmentData,
                    Position = i
                });
            }
            
            return segments;
        }

        private byte[] EncryptWithChaCha20(byte[] data, byte[] key, byte[] nonce)
        {
            using var cipher = new ChaCha20Poly1305(key);
            var ciphertext = new byte[data.Length];
            var tag = new byte[16];
            
            cipher.Encrypt(nonce, data, ciphertext, tag);
            
            // Combine ciphertext + tag
            var result = new byte[ciphertext.Length + tag.Length];
            ciphertext.CopyTo(result, 0);
            tag.CopyTo(result, ciphertext.Length);
            
            return result;
        }

        private byte[] DecryptWithChaCha20(byte[] encryptedData, byte[] key, byte[] nonce)
        {
            using var cipher = new ChaCha20Poly1305(key);
            
            // Split ciphertext and tag
            var ciphertext = new byte[encryptedData.Length - 16];
            var tag = new byte[16];
            
            Array.Copy(encryptedData, 0, ciphertext, 0, ciphertext.Length);
            Array.Copy(encryptedData, ciphertext.Length, tag, 0, 16);
            
            var plaintext = new byte[ciphertext.Length];
            cipher.Decrypt(nonce, ciphertext, tag, plaintext);
            
            return plaintext;
        }

        private byte[] DeriveSegmentKey(int position)
        {
            var input = $"{_baseKey}:segment:{position}:{_rotationCounter}";
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(input));
            
            // Use PBKDF2 for key stretching
            using var pbkdf2 = new Rfc2898DeriveBytes(hash, 
                BitConverter.GetBytes(position), 
                10000, 
                HashAlgorithmName.SHA256);
                
            return pbkdf2.GetBytes(32);
        }

        private byte[] ObfuscateMetadata(List<EncryptedSegment> segments)
        {
            var metadata = new byte[segments.Count * 32]; // 32 bytes per segment metadata
            var obfuscationKey = _currentPolymorphicKey;
            
            for (int i = 0; i < metadata.Length; i++)
            {
                metadata[i] = (byte)(segments[i / 32].Position ^ 
                                   obfuscationKey[i % obfuscationKey.Length] ^ 
                                   _rotationCounter);
            }
            
            return metadata;
        }

        private byte[] GeneratePolymorphicKey()
        {
            var input = $"{_baseKey}:{DateTime.UtcNow.Ticks}:{_rotationCounter}:{Environment.ProcessId}";
            return SHA256.HashData(Encoding.UTF8.GetBytes(input));
        }

        private void RotateKeys(object? state)
        {
            lock (_lockObject)
            {
                _rotationCounter++;
                var oldKey = _currentPolymorphicKey;
                _currentPolymorphicKey = GeneratePolymorphicKey();
                
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
                // Securely wipe all stored commands
                foreach (var command in _commands.Values)
                {
                    foreach (var segment in command.Segments)
                    {
                        RandomNumberGenerator.Fill(segment.Data);
                        RandomNumberGenerator.Fill(segment.Nonce);
                    }
                    RandomNumberGenerator.Fill(command.ObfuscatedMetadata);
                }
                _commands.Clear();
                
                // Wipe keys
                if (_currentPolymorphicKey != null)
                {
                    RandomNumberGenerator.Fill(_currentPolymorphicKey);
                }
            }
        }

        private class MemoryCommand
        {
            public List<EncryptedSegment> Segments { get; set; } = new();
            public byte[] ObfuscatedMetadata { get; set; } = Array.Empty<byte>();
            public DateTime CreatedAt { get; set; }
            public int AccessCount { get; set; }
        }

        private class EncryptedSegment
        {
            public byte[] Data { get; set; } = Array.Empty<byte>();
            public byte[] Nonce { get; set; } = Array.Empty<byte>();
            public int Position { get; set; }
            public int Size { get; set; }
        }

        private class CommandSegment
        {
            public byte[] Data { get; set; } = Array.Empty<byte>();
            public int Position { get; set; }
        }
    }
}