using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NoEdgeCrypto.Core;

namespace NoEdgeSoftware.Cryptography.Tests
{
    [TestClass]
    public class SecureRandomizerTests
        : BaseTest
    {
        /// <summary>
        /// Ensures 100,000 runs of 32 bytes takes less than 2 seconds (should take significantly less).
        /// </summary>
        [TestMethod]
        public void TestSpeed()
        {
            var sw = new Stopwatch();
            sw.Start();
            var bytes = new byte[32];
            for (int i = 0; i < 100000; ++i)
            {
                bytes = SecureRandomizer.GetRandomBytes(bytes.Length);
            }

            Assert.IsTrue(sw.ElapsedMilliseconds < 2000, "Should have taken less than two seconds");
        }

        /// <summary>
        /// Ensures that the randomizer does not produce an empty array (all zeros). Runs 500,000 times.
        /// </summary>
        [TestMethod]
        public void TestNotEmptyArray()
        {
            var bytes = new byte[32];
            for (int i = 0; i < 500000; ++i)
            {
                bytes = SecureRandomizer.GetRandomBytes(bytes.Length);
                bool anyNotZero = false;
                foreach (var b in bytes)
                {
                    anyNotZero |= (b != 0);
                }
                Assert.IsTrue(anyNotZero, "Array is full of zeros");
            }
        }

        /// <summary>
        /// Ensures that after running the randomizer 500,000 times, every position (32 positions) receives every
        /// possible byte. Statistically certain if the algorithm is random.
        /// </summary>
        [TestMethod]
        public void TestAllPositionsContainsAllBytes()
        {
            var byteValuesByPosition = new HashSet<byte>[32];
            for (int i = 0; i < 32; ++i)
            {
                byteValuesByPosition[i] = new HashSet<byte>();
            }

            var bytes = new byte[32];
            for (int i = 0; i < 500000; ++i)
            {
                bytes = SecureRandomizer.GetRandomBytes(bytes.Length);

                for (int j = 0; j < 32; ++j)
                {
                    byteValuesByPosition[j].Add(bytes[j]);
                }
            }

            for (int i = 0; i < 32; ++i)
            {
                Assert.AreEqual(256, byteValuesByPosition[i].Count, "Position {0} does not contain all 256 possible values", i);
            }
        }

        [TestMethod]
        public void TestThreadSafety()
        {
            var hashset = new HashSet<string>();

            ThreadStart action = () =>
            {
                for (int i = 0; i < 50000; ++i)
                {
                    byte[] bytes = SecureRandomizer.GetRandomBytes(32);
                    lock (hashset)
                    {
                        hashset.Add(Convert.ToBase64String(bytes));
                    }
                }
            };

            var threads = new Thread[10];
            for (int i = 0; i < threads.Length; ++i)
            {
                var thread = new Thread(action);
                threads[i] = thread;
                thread.Start();
            }
            foreach (var t in threads)
            {
                while (t.IsAlive)
                {
                }
            }

            Assert.AreEqual(500000, hashset.Count, "Number of unique arrays");
        }

        [TestMethod]
        public void TestThreadSafetyParallel()
        {
            var hashset = new HashSet<string>();

            Action<int> action = idx =>
            {
                for (int i = 0; i < 50000; ++i)
                {
                    byte[] bytes = SecureRandomizer.GetRandomBytes(32);
                    lock (hashset)
                    {
                        hashset.Add(Convert.ToBase64String(bytes));
                    }
                }
            };

            var parallelLoopResult = Parallel.For(0, 10, action);

            while (!parallelLoopResult.IsCompleted) { }

            Assert.AreEqual(500000, hashset.Count, "Number of unique arrays");
        }

        /// <summary>
        /// Ensures that there are never 16 of the same bytes in an array. Statistically impossible. Runs
        /// 500,000 times.
        /// </summary>
        [TestMethod]
        public void TestNoMoreThan16OfTheSameByte()
        {
            var bytes = new byte[32];
            for (int i = 0; i < 500000; ++i)
            {
                bytes = SecureRandomizer.GetRandomBytes(bytes.Length);
                var countByValue = new Dictionary<byte, int>();
                foreach (byte b in bytes)
                {
                    if (!countByValue.ContainsKey(b))
                    {
                        countByValue[b] = 1;
                    }
                    else
                    {
                        ++countByValue[b];
                    }
                }
                foreach (var kvp in countByValue)
                {
                    if (kvp.Value >= 16)
                    {
                        Assert.Fail("Value {0} appeared 16 or more times", kvp.Key);
                    }
                }
            }
        }

        /// <summary>
        /// Runs the randomizer 500,000 times, and ensures that every run gets a unique array.
        /// </summary>
        [TestMethod]
        public void TestAllArraysUnique()
        {
            var hashset = new HashSet<string>();
            var bytes = new byte[32];
            for (int i = 0; i < 500000; ++i)
            {
                bytes = SecureRandomizer.GetRandomBytes(bytes.Length);
                hashset.Add(Convert.ToBase64String(bytes));
            }
            Assert.AreEqual(500000, hashset.Count, "Number of unique arrays");
        }

        /// <summary>
        /// Runs 20 large arrays (100,000 bytes), and ensures they are all unique. 100,000 bytes is more
        /// than the buffer size, so it will reset the buffer.
        /// </summary>
        [TestMethod]
        public void TestTooLargeArrayStillWorks()
        {
            var hashset = new HashSet<string>();
            for (int i = 0; i < 20; ++i)
            {
                hashset.Add(Convert.ToBase64String(SecureRandomizer.GetRandomBytes(100000)));
            }

            Assert.AreEqual(20, hashset.Count, "Number of unique arrays");
        }

        /// <summary>
        /// Tests 10,000 arrays of 1,234 bytes each, to make the buffer reset in the middle of various arrays.
        /// </summary>
        [TestMethod]
        public void TestUnevenArraySize()
        {
            var hashset = new HashSet<string>();
            for (int i = 0; i < 10000; ++i)
            {
                hashset.Add(Convert.ToBase64String(SecureRandomizer.GetRandomBytes(1234)));
            }

            Assert.AreEqual(10000, hashset.Count, "Number of unique arrays");
        }
    }
}
