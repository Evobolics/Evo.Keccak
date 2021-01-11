using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Evo.Services.Cryptography
{
    public class KeccakServiceBase
    {
        /// <summary>
        /// Contain the twenty four round contants.  
        /// </summary>
        /// <remarks>
        /// These constants are only used in the Iota Step of the round function.  
        /// The reason there are twenty-four is because the max number of rounds
        /// Keccak supports using formula 12 + 2l where l ranges from 0 to 6.  Thus
        /// all implementations of the Keccak algorithm can use same set of round constants.  
        /// </remarks>
        public static readonly ulong[] RoundConstants =
        {
            0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL,
            0x8000000080008000UL, 0x000000000000808bUL, 0x0000000080000001UL,
            0x8000000080008081UL, 0x8000000000008009UL, 0x000000000000008aUL,
            0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
            0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL,
            0x8000000000008003UL, 0x8000000000008002UL, 0x8000000000000080UL,
            0x000000000000800aUL, 0x800000008000000aUL, 0x8000000080008081UL,
            0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
        };
    }
}
