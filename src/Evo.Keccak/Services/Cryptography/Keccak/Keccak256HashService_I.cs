using System;

namespace Evo.Services.Cryptography
{
    public interface Keccak256HashService_I
    {
        /// <summary>
        /// Computes a Keccak 256 bit hash.
        /// </summary>
        /// <param name="input">A contiguous region of arbitrary memory with the bytes to hash.</param>
        /// <param name="output">A contiguous region of arbitrary memory that will be updated with the computed hash.</param>
        void ComputeHash(Span<byte> input, Span<byte> output);
    }
}
