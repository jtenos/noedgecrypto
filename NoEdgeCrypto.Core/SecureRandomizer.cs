using System;
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace NoEdgeCrypto.Core
{
    /// <summary>
    /// A class for generating random bytes using .NET's RandomNumberGenerator.Create. A ConcurrentQueue exists
    /// which is populated as needed, and bytes are retrieved from this queue as needed. 
    /// </summary>
    public static class SecureRandomizer
    {
        private static readonly ConcurrentQueue<byte> _queue = new ConcurrentQueue<byte>();

        /// <summary>
        /// Retrieves random bytes from the queue.
        /// </summary>
        /// <param name="numBytes">The size of the byte array.</param>
        /// <returns>The random bytes.</returns>
        public static byte[] GetRandomBytes(int numBytes)
        {
            if (numBytes < 0)
            {
                throw new ArgumentException("Number of bytes must be non-negative");
            }
            if (numBytes == 0)
            {
                return new byte[0];
            }

            var result = new byte[numBytes];
            for (int i = 0; i < numBytes; ++i)
            {
                byte b;
                while (!_queue.TryDequeue(out b))
                {
                    RepopulateQueue();
                }
                result[i] = b;
            }
            return result;
        }

        private static void RepopulateQueue()
        {
            const int QUEUE_SIZE = 1 << 12;
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] bytes = new byte[QUEUE_SIZE];
                rng.GetBytes(bytes);
                foreach (byte b in bytes)
                {
                    _queue.Enqueue(b);
                }
            }
        }
    }
}
