using Evo.Keccak;
using Evo.Services.Cryptography;
using Evo.Statics;
using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace Evo.Models.Cryptography
{
    public class Keccak256Hash
    {
        // For useful links discussing the Keccak algorithm and additional notes, please see: 
        //
        //      https://github.com/Evobolics/Ethereum/blob/main/README.md

        // ¹²³⁴⁵⁶⁷⁸⁹⁰ᵃᵇᶜᵈᵉᶠᵍʰⁱʲᵏˡᵐⁿᵒᵖʳˢᵗᵘᵛʷˣʸᶻ
        // ₀₁₂₃₄₅₆₇₈₉ₐ ₑ ₕ ᵢ ⱼ ₖ ₗ ₘ ₙ ₒ ₚ ᵣ ₛ ₜ ᵤ ᵥ ₓ 


        // The state 'a', is organized into a 3D structure that is composed of an array of 5 x 5 lanes  
        // with each lane being w bits in length.  
        //
        //      a = [5][5][w]
        //
        // Each position in the 3D array 'a' stores one bit of information, and the position represents an
        // 3D coordinate.  
        //
        //      a = [x][y][z], with x ranging from 0..4, y ranging from 0..4, and z ranging from 0 to w-1.

        // Thus the state expression a[x][y][z] denotes a bit in position(x, y, z), where x and y can range 
        // from values 0 to 4, and z can range from values from 0 to w-1, depending upon which variant
        // of the Keccak algorithm is implemented.
        // 
        // The number of w bits in length is determined by
        // what well defined variants or permutation of the Keccak algorithm is being used.  There are a total of
        // seven well defined Keccak-f permutations or variants.  The  permuations are numbered 0
        // through 6, with a value of l being assigned to each permutation.  
        //
        //      l = {0, 1, 2, 3, 4, 5, 6}
        // 
        // For each permutation or algorithm variant, the length of the lane is defined to be 2^l.  
        //
        //      w = lane length in bits
        //      w = 2ˡ bits; 
        //        or
        //      w = {1, 2, 4, 8, 16, 32, 64} bits
        //  
        // The name of the permutation or variant is defined as "Keccak-f[b]", with b being defined as 
        // twenty-five times 2 to the power of l, where l is the numbered instance of the permutation.  
        // Twenty-five comes from the array of 25 bits, and the 2ˡ is the number bits each of 25 lanes 
        // are in length.  
        //
        //      b = state size
        //      b = 25 x 2ˡ ; 
        //      b = {25, 50, 100, 200, 400, 800, 1600}
        //
        // Thus for variant 0, the state size is 25.  For variant 1, the state size is 50, and so forth.  
        // From these state sizes, the names of the seven well defined Keccak varients are derived:
        // 
        //      Keccak-f[25]    with state size being 25 bits
        //      Keccak-f[50]    with state size being 50 bits
        //      Keccak-f[100]   with state size being 100 bits
        //      Keccak-f[200]   with state size being 200 bits
        //      Keccak-f[400]   with state size being 400 bits
        //      Keccak-f[800]   with state size being 800 bits
        //      Keccak-f[1600]  with state size being 1600 bits  
        //
        // The varient Keccak-f[1600] was choosen to be implemented.  See // https://keccak.team/files/Keccak-submission-3.pdf.

        // The algorithm maps all the bits, b, to a one dimensional array s who has a length of b.  
        //
        //     a[x][y][z] = s[w(5y + x) + z]
        //



        #region Fields


        public int RoundSize;
        public int RoundSizeU64;
        public Memory<byte> RemainderBuffer;
        public int RemainderLength;
        public Memory<ulong> State;
        internal byte[] _hash;
        #endregion

        #region Constructor
        public Keccak256Hash()
        {

        }
        #endregion

        #region Properties
        public static byte[] BLANK_HASH
        {
            get
            {
                return KeccakRoot.Keccak256.ComputeHashBytes(Array.Empty<byte>());
            }
        }

        /// <summary>
        /// Indicates the hash size in bytes.
        /// </summary>
        public int HashSize { get; set; }

        /// <summary>
        /// The current hash buffer at this point. Recomputed after hash updates.
        /// </summary>
        public byte[] Hash
        {
            get
            {
                // If the hash is null, recalculate.
                _hash = _hash ?? KeccakRoot.Keccak256.UpdateFinal(this);

                // Return it.
                return _hash;
            }
        }
        #endregion

       

    

    }
}
