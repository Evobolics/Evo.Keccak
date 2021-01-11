using Evo.Statics;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace System
{
    public static class StringExtensions
    {
        public static byte[] HashToKeccak256(this string input)
        {
            return KeccakRoot.Keccak256.FromString(input);
        }
    }
}
