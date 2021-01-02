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
        

        private int _roundSize;
        private int _roundSizeU64;
        private Memory<byte> _remainderBuffer;
        private int _remainderLength;
        private Memory<ulong> _state;
        private byte[] _hash;
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
        public int HashSize { get; }

        /// <summary>
        /// The current hash buffer at this point. Recomputed after hash updates.
        /// </summary>
        public byte[] Hash
        {
            get
            {
                // If the hash is null, recalculate.
                _hash = _hash ?? UpdateFinal();

                // Return it.
                return _hash;
            }
        }
        #endregion

        #region Constructor
        public Keccak256Hash(int size)
        {
            // Set the hash size
            HashSize = size;

            // Verify the size
            if (HashSize <= 0 || HashSize > Keccak256Service.State_Size_B_InBytes)
            {
                throw new ArgumentException($"Invalid Keccak hash size. Must be between 0 and {Keccak256Service.State_Size_B_InBytes}.");
            }

            // The round size.
            _roundSize = Keccak256Service.State_Size_B_InBytes == HashSize ? Keccak256Service.HASH_DATA_AREA : Keccak256Service.State_Size_B_InBytes - 2 * HashSize;

            // The size of a round in terms of ulong.
            _roundSizeU64 = _roundSize / 8;

            // Allocate our remainder buffer
            _remainderBuffer = new byte[_roundSize];
            _remainderLength = 0;
        }
        #endregion

        #region Functions

       

        public void Update(byte[] array, int index, int size)
        {
            // Bounds checking.
            if (size < 0)
            {
                throw new ArgumentException("Cannot updated Keccak hash because the provided size of data to hash is negative.");
            }
            else if (index + size > array.Length || index < 0)
            {
                throw new ArgumentOutOfRangeException("Cannot updated Keccak hash because the provided index and size extend outside the bounds of the array.");
            }

            // If the size is zero, quit
            if (size == 0)
            {
                return;
            }

            // Create the input buffer
            Span<byte> input = array;
            input = input.Slice(index, size);

            // If our provided state is empty, initialize a new one
            if (_state.Length == 0)
            {
                _state = new ulong[Keccak256Service.State_Size_B_InBytes / 8];
            }

            // If our remainder is non zero.
            int i;
            if (_remainderLength != 0)
            {
                // Copy data to our remainder
                var remainderAdditive = input.Slice(0, Math.Min(input.Length, _roundSize - _remainderLength));
                remainderAdditive.CopyTo(_remainderBuffer.Slice(_remainderLength).Span);

                // Increment the length
                _remainderLength += remainderAdditive.Length;

                // Increment the input
                input = input.Slice(remainderAdditive.Length);

                // If our remainder length equals a full round
                if (_remainderLength == _roundSize)
                {
                    // Cast our input to ulongs.
                    var remainderBufferU64 = MemoryMarshal.Cast<byte, ulong>(_remainderBuffer.Span);

                    // Loop for each ulong in this remainder, and xor the state with the input.
                    for (i = 0; i < _roundSizeU64; i++)
                    {
                        _state.Span[i] ^= remainderBufferU64[i];
                    }

                    // Perform our keccakF on our state.
                    KeccakRoot.Keccak256.KeccakF(_state.Span, Keccak256Service.ROUNDS);

                    // Clear remainder fields
                    _remainderLength = 0;
                    _remainderBuffer.Span.Clear();
                }
            }

            // Loop for every round in our size.
            while (input.Length >= _roundSize)
            {
                // Cast our input to ulongs.
                var input64 = MemoryMarshal.Cast<byte, ulong>(input);

                // Loop for each ulong in this round, and xor the state with the input.
                for (i = 0; i < _roundSizeU64; i++)
                {
                    _state.Span[i] ^= input64[i];
                }

                // Perform our keccakF on our state.
                KeccakRoot.Keccak256.KeccakF(_state.Span, Keccak256Service.ROUNDS);

                // Remove the input data processed this round.
                input = input.Slice(_roundSize);
            }

            // last block and padding
            if (input.Length >= Keccak256Service.TEMP_BUFF_SIZE || input.Length > _roundSize || _roundSize + 1 >= Keccak256Service.TEMP_BUFF_SIZE || _roundSize == 0 || _roundSize - 1 >= Keccak256Service.TEMP_BUFF_SIZE || _roundSizeU64 * 8 > Keccak256Service.TEMP_BUFF_SIZE)
            {
                throw new ArgumentException("Bad keccak use");
            }

            // If we have any remainder here, it means any remainder was processed before, we can copy our data over and set our length
            if (input.Length > 0)
            {
                input.CopyTo(_remainderBuffer.Span);
                _remainderLength = input.Length;
            }

            // Set the hash as null
            _hash = null;
        }

        private byte[] UpdateFinal()
        {
            // Copy the remainder buffer
            Memory<byte> remainderClone = _remainderBuffer.ToArray();

            // Set a 1 byte after the remainder.
            remainderClone.Span[_remainderLength++] = 1;

            // Set the highest bit on the last byte.
            remainderClone.Span[_roundSize - 1] |= 0x80;

            // Cast the remainder buffer to ulongs.
            var temp64 = MemoryMarshal.Cast<byte, ulong>(remainderClone.Span);

            // Loop for each ulong in this round, and xor the state with the input.
            for (int i = 0; i < _roundSizeU64; i++)
            {
                _state.Span[i] ^= temp64[i];
            }

            KeccakRoot.Keccak256.KeccakF(_state.Span, Keccak256Service.ROUNDS);

            // Obtain the state data in the desired (hash) size we want.
            _hash = MemoryMarshal.AsBytes(_state.Span).Slice(0, HashSize).ToArray();

            // Return the result.
            return Hash;
        }

        public void Reset()
        {
            // Clear our hash state information.
            _state.Span.Clear();
            _remainderBuffer.Span.Clear();
            _remainderLength = 0;
            _hash = null;
        }
        #endregion

    }
}
