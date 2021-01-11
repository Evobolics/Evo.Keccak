﻿using Evo.Models.Cryptography;
using Evo.Services.Cryptography.Keccak;
using Evo.Statics;
using System;

using Xunit;

namespace Evo.Keccak.Tests
{
    public class KeccakTests
    {
        /// <summary>
        /// Verifies that Keccak256 hashing functions are working accordingly.
        /// </summary>
        [Theory]
        [InlineData("4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15", "The quick brown fox jumps over the lazy dog", true)]
        [InlineData("578951e24efd62a3d63a86f7cd19aaa53c898fe287d2552133220370240b572d", "The quick brown fox jumps over the lazy dog.", true)]
        [InlineData("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", "", true)]
        [InlineData("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a471", "", false)]
        [InlineData("70a2b6579047f0a977fcb5e9120a4e07067bea9abb6916fbc2d13ffb9a4e4eee", "中文", true)]
        [InlineData("d7d569202f04daf90432810d6163112b2695d7820da979327ebd894efb0276dc", "aécio", true)]
        [InlineData("16a7cc7a58444cbf7e939611910ddc82e7cba65a99d3e8e08cfcda53180a2180", "𠜎", true)]
        [InlineData("d1021d2d4c5c7e88098c40f422af68493b4b64c913cbd68220bf5e6127c37a88", "訊息摘要演算法第五版（英語：Message-Digest Algorithm 5，縮寫為MD5），是當前電腦領域用於確保資訊傳輸完整一致而廣泛使用的雜湊演算法之一", true)]
        [InlineData("ffabf9bba2127c4928d360c9905cb4911f0ec21b9c3b89f3b242bccc68389e36", "訊息摘要演算法第五版（英語：Message-Digest Algorithm 5，縮寫為MD5），是當前電腦領域用於確保資訊傳輸完整一致而廣泛使用的雜湊演算法之一（又譯雜湊演算法、摘要演算法等），主流程式語言普遍已有MD5的實作。", true)]
        public void TestKeccak1600_Teaching1Algorithm(string expected, string input, bool shouldMatch)
        {
            var teaching = new Keccak1600Service_Teaching1();

            var result = teaching.FromString(input).ToHexString(hexPrefix: false);
            if (shouldMatch)
            {
                Assert.Equal(expected, result);
            }
            else
            {
                Assert.NotEqual(expected, result);
            }
        }

        /// <summary>
        /// Verifies that Keccak256 hashing functions are working accordingly.
        /// </summary>
        [Theory]
        [InlineData("4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15", "The quick brown fox jumps over the lazy dog", true)]
        [InlineData("578951e24efd62a3d63a86f7cd19aaa53c898fe287d2552133220370240b572d", "The quick brown fox jumps over the lazy dog.", true)]
        [InlineData("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", "", true)]
        [InlineData("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a471", "", false)]
        [InlineData("70a2b6579047f0a977fcb5e9120a4e07067bea9abb6916fbc2d13ffb9a4e4eee", "中文", true)]
        [InlineData("d7d569202f04daf90432810d6163112b2695d7820da979327ebd894efb0276dc", "aécio", true)]
        [InlineData("16a7cc7a58444cbf7e939611910ddc82e7cba65a99d3e8e08cfcda53180a2180", "𠜎", true)]
        [InlineData("d1021d2d4c5c7e88098c40f422af68493b4b64c913cbd68220bf5e6127c37a88", "訊息摘要演算法第五版（英語：Message-Digest Algorithm 5，縮寫為MD5），是當前電腦領域用於確保資訊傳輸完整一致而廣泛使用的雜湊演算法之一", true)]
        [InlineData("ffabf9bba2127c4928d360c9905cb4911f0ec21b9c3b89f3b242bccc68389e36", "訊息摘要演算法第五版（英語：Message-Digest Algorithm 5，縮寫為MD5），是當前電腦領域用於確保資訊傳輸完整一致而廣泛使用的雜湊演算法之一（又譯雜湊演算法、摘要演算法等），主流程式語言普遍已有MD5的實作。", true)]
        public void TestKeccak1600_Teaching2Algorithm(string expected, string input, bool shouldMatch)
        {
            var teaching = new Keccak1600Service_Teaching2();

            var result = teaching.FromString(input).ToHexString(hexPrefix: false);
            if (shouldMatch)
            {
                Assert.Equal(expected, result);
            }
            else
            {
                Assert.NotEqual(expected, result);
            }
        }

        /// <summary>
        /// Verifies that Keccak256 hashing functions are working accordingly.
        /// </summary>
        [Theory]
        [InlineData("4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15", "The quick brown fox jumps over the lazy dog", true)]
        [InlineData("578951e24efd62a3d63a86f7cd19aaa53c898fe287d2552133220370240b572d", "The quick brown fox jumps over the lazy dog.", true)]
        [InlineData("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", "", true)]
        [InlineData("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a471", "", false)]
        [InlineData("70a2b6579047f0a977fcb5e9120a4e07067bea9abb6916fbc2d13ffb9a4e4eee", "中文", true)]
        [InlineData("d7d569202f04daf90432810d6163112b2695d7820da979327ebd894efb0276dc", "aécio", true)]
        [InlineData("16a7cc7a58444cbf7e939611910ddc82e7cba65a99d3e8e08cfcda53180a2180", "𠜎", true)]
        [InlineData("d1021d2d4c5c7e88098c40f422af68493b4b64c913cbd68220bf5e6127c37a88", "訊息摘要演算法第五版（英語：Message-Digest Algorithm 5，縮寫為MD5），是當前電腦領域用於確保資訊傳輸完整一致而廣泛使用的雜湊演算法之一", true)]
        [InlineData("ffabf9bba2127c4928d360c9905cb4911f0ec21b9c3b89f3b242bccc68389e36", "訊息摘要演算法第五版（英語：Message-Digest Algorithm 5，縮寫為MD5），是當前電腦領域用於確保資訊傳輸完整一致而廣泛使用的雜湊演算法之一（又譯雜湊演算法、摘要演算法等），主流程式語言普遍已有MD5的實作。", true)]
        public void TestKeccakHashing(string expected, string input, bool shouldMatch)
        {
            var result = KeccakRoot.Keccak256.FromString(input).ToHexString(hexPrefix: false);
            if (shouldMatch)
            {
                Assert.Equal(expected, result);
            }
            else
            {
                Assert.NotEqual(expected, result);
            }
        }

        [Theory]
        [InlineData("4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15", "The quick brown fox jumps over the lazy dog", true)]
        public void KeccakFromString(string expected, string input, bool shouldMatch)
        {
            var result = input.HashToKeccak256Bytes().ToHexString(hexPrefix: false);

            if (shouldMatch)
            {
                Assert.Equal(expected, result);
            }
            else
            {
                Assert.NotEqual(expected, result);
            }
        }

        [Theory]
        [InlineData("4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15", "The quick brown fox jumps over the lazy dog", true)]
        public void TestHashToKeccak256Bytes(string expected, string input, bool shouldMatch)
        {
            var bytes = input.GetUtf8Bytes();

            var result = bytes.HashToKeccak256Bytes().ToHexString();

            if (shouldMatch)
            {
                Assert.Equal(expected, result);
            }
            else
            {
                Assert.NotEqual(expected, result);
            }
        }

        [Theory]
        [InlineData("4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15", "The quick brown fox jumps over the lazy dog", true)]
        public void TestHashToKeccak256Span(string expected, string input, bool shouldMatch)
        {
            var bytes = input.GetUtf8Bytes();

            var result = bytes.HashToKeccak256Span().ToHexString();

            if (shouldMatch)
            {
                Assert.Equal(expected, result);
            }
            else
            {
                Assert.NotEqual(expected, result);
            }
        }

        [Fact]
        public void TestKeccakUpdate()
        {
            // Create our random provider.
            Random random = new Random();

            // Loop for a few test rounds.
            for (int i = 0; i < 5; i++)
            {
                // Generate random data
                byte[] bufferArray = new byte[random.Next(3, 1024 * 20)];
                Span<byte> buffer = bufferArray;
                random.NextBytes(buffer);

                // Split threshold
                int splitThreshold = random.Next(33, 1024);

                // Compute the overall hash on the data
                byte[] singleStepHash = KeccakRoot.Keccak256.ComputeHashBytes(buffer);

                // Create our keccak hash provider for multi step hash calculation.
                Keccak256 keccak = KeccakRoot.Keccak256.Create();
                keccak.Update(bufferArray, 0, buffer.Length);

                // Assert the hashes are equal
                Assert.Equal(singleStepHash.ToHexString(), keccak.Hash.ToHexString());

                // Recompute on the same keccak instance to check if it's reusable.
                keccak.Reset();
                keccak.Update(bufferArray, 0, buffer.Length);
                Assert.Equal(singleStepHash.ToHexString(), keccak.Hash.ToHexString());

                // Recompute the hash but add empty array hashing.
                keccak.Reset();
                keccak.Update(bufferArray, 0, bufferArray.Length);
                keccak.Update(Array.Empty<byte>(), 0, 0);
                keccak.Update(Array.Empty<byte>(), 0, 0);

                // Assert the hashes are equal
                Assert.Equal(singleStepHash.ToHexString(), keccak.Hash.ToHexString());

                // Assert blank hashes
                keccak.Reset();
                keccak.Update(Array.Empty<byte>(), 0, 0);
                keccak.Update(Array.Empty<byte>(), 0, 0);
                byte[] blankHash = KeccakRoot.Keccak256.ComputeHashBytes(Array.Empty<byte>());
                Assert.Equal(blankHash.ToHexString(), keccak.Hash.ToHexString());

                // Refresh our new keccak instance
                keccak.Reset();

                while (buffer.Length > 0)
                {
                    // Check if this is the last round
                    bool lastRound = buffer.Length <= splitThreshold;

                    // Obtain the data for this round.
                    byte[] roundData = buffer.Slice(0, lastRound ? buffer.Length : splitThreshold).ToArray();

                    if (lastRound)
                    {
                        // Obtain the final multistep hash.
                        keccak.Update(roundData, 0, roundData.Length);

                        // Assert the hashes are equal
                        Assert.Equal(singleStepHash.ToHexString(), keccak.Hash.ToHexString());

                        // Reset
                        keccak.Reset();
                        break;
                    }
                    else
                    {
                        keccak.Update(roundData, 0, roundData.Length);
                    }

                    // Advance our pointer.
                    buffer = buffer.Slice(roundData.Length);
                }
            }
        }
    }
}
