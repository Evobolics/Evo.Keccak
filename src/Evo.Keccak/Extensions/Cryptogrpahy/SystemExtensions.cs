using Evo.Statics;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace System
{
    public static class SystemExtensions
    {
        public static byte[] HashToKeccak256Bytes(this string input)
        {
            return KeccakRoot.Keccak256.FromString(input);
        }

        public static Span<byte> HashToKeccak256Span(this byte[] input)
        {
            return KeccakRoot.Keccak256.ComputeHash(input);
        }

        public static byte[] HashToKeccak256Bytes(this byte[] input)
        {
            return KeccakRoot.Keccak256.ComputeHashBytes(input);
        }
    }
}
