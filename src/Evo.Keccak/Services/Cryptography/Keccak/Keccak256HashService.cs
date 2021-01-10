using Evo.Keccak;
using Evo.Models.Cryptography;
using Evo.Statics;
using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace Evo.Services.Cryptography
{
    public class Keccak256HashService : Keccak256HashService_I
    {
        #region Constants
        public const int State_Size_B_InBits = 1600;
        public const int State_Size_B_InBytes = State_Size_B_InBits / 8; // Value = 1600 / 8 = 200;
        public const int HASH_SIZE_InBytes = 32; // 256 bits
        public const int HASH_DATA_AREA = 136;
        public const int ROUNDS = 24;
        public const int LANE_BITS = 8 * 8;
        public const int TEMP_BUFF_SIZE = 144;
        #endregion

        #region Static Fields
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

        static readonly ArrayPool<byte> _arrayPool = ArrayPool<byte>.Shared;

        #endregion

        //public Keccak256 Create(byte[] bytes)
        //{
        //    return new Keccak256();
        //}

        //public Keccak256RefStruct CreateRefStruct(byte[] bytes)
        //{
        //    return new Keccak256RefStruct();
        //}

        public Keccak256 Create(int size = HASH_SIZE_InBytes)
        {
            Keccak256 keccak = new Keccak256();

            // Set the hash size
            keccak.HashSize = size;

            // Verify the size
            if (keccak.HashSize <= 0 || keccak.HashSize > State_Size_B_InBytes)
            {
                throw new ArgumentException($"Invalid Keccak hash size. Must be between 0 and {State_Size_B_InBytes}.");
            }

            // The round size.
            keccak.RoundSize = State_Size_B_InBytes == keccak.HashSize ? HASH_DATA_AREA : State_Size_B_InBytes - 2 * keccak.HashSize;

            // The size of a round in terms of ulong.
            keccak.RoundSizeU64 = keccak.RoundSize / 8;

            // Allocate our remainder buffer
            keccak.RemainderBuffer = new byte[keccak.RoundSize];
            keccak.RemainderLength = 0;

            return keccak;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private ulong ROL(ulong a, int offset)
        {
            return a << offset % LANE_BITS ^ a >> LANE_BITS - offset % LANE_BITS;
        }

        // update the state with given number of rounds
        public void KeccakF(Span<ulong> st, int rounds = ROUNDS)
        {
            Debug.Assert(st.Length == 25);

            ulong a04, a14, a24, a34, a44;
            ulong a03, a13, a23, a33, a43;
            ulong a02, a12, a22, a32, a42;
            ulong a01, a11, a21, a31, a41;
            ulong a00, a10, a20, a30, a40;

            ulong C0, C1, C2, C3, C4;
            ulong D0, D1, D2, D3, D4;

            ulong b04, b14, b24, b34, b44;
            ulong b03, b13, b23, b33, b43;
            ulong b02, b12, b22, b32, b42;
            ulong b01, b11, b21, b31, b41;
            ulong b00, b10, b20, b30, b40;

            //copyFromState(A, state)
            a00 = st[0];
            a10 = st[1];
            a20 = st[2];
            a30 = st[3];
            a40 = st[4];
            a01 = st[5];
            a11 = st[6];
            a21 = st[7];
            a31 = st[8];
            a41 = st[9];
            a02 = st[10];
            a12 = st[11];
            a22 = st[12];
            a32 = st[13];
            a42 = st[14];
            a03 = st[15];
            a13 = st[16];
            a23 = st[17];
            a33 = st[18];
            a43 = st[19];
            a04 = st[20];
            a14 = st[21];
            a24 = st[22];
            a34 = st[23];
            a44 = st[24];

            for (var round = 0; round < rounds; round += 2)
            {
                //    prepareTheta
                C0 = a00 ^ a01 ^ a02 ^ a03 ^ a04;
                C1 = a10 ^ a11 ^ a12 ^ a13 ^ a14;
                C2 = a20 ^ a21 ^ a22 ^ a23 ^ a24;
                C3 = a30 ^ a31 ^ a32 ^ a33 ^ a34;
                C4 = a40 ^ a41 ^ a42 ^ a43 ^ a44;

                //thetaRhoPiChiIotaPrepareTheta(round  , A, E)
                D0 = C4 ^ ROL(C1, 1);
                D1 = C0 ^ ROL(C2, 1);
                D2 = C1 ^ ROL(C3, 1);
                D3 = C2 ^ ROL(C4, 1);
                D4 = C3 ^ ROL(C0, 1);

                a00 ^= D0;
                C0 = a00;
                a11 ^= D1;
                C1 = ROL(a11, 44);
                a22 ^= D2;
                C2 = ROL(a22, 43);
                a33 ^= D3;
                C3 = ROL(a33, 21);
                a44 ^= D4;
                C4 = ROL(a44, 14);

                b00 = C0 ^ ~C1 & C2;
                b00 ^= RoundConstants[round];
                b10 = C1 ^ ~C2 & C3;
                b20 = C2 ^ ~C3 & C4;
                b30 = C3 ^ ~C4 & C0;
                b40 = C4 ^ ~C0 & C1;

                a30 ^= D3;
                C0 = ROL(a30, 28);
                a41 ^= D4;
                C1 = ROL(a41, 20);
                a02 ^= D0;
                C2 = ROL(a02, 3);
                a13 ^= D1;
                C3 = ROL(a13, 45);
                a24 ^= D2;
                C4 = ROL(a24, 61);
                b01 = C0 ^ ~C1 & C2;
                b11 = C1 ^ ~C2 & C3;
                b21 = C2 ^ ~C3 & C4;
                b31 = C3 ^ ~C4 & C0;
                b41 = C4 ^ ~C0 & C1;

                a10 ^= D1;
                C0 = ROL(a10, 1);
                a21 ^= D2;
                C1 = ROL(a21, 6);
                a32 ^= D3;
                C2 = ROL(a32, 25);
                a43 ^= D4;
                C3 = ROL(a43, 8);
                a04 ^= D0;
                C4 = ROL(a04, 18);
                b02 = C0 ^ ~C1 & C2;
                b12 = C1 ^ ~C2 & C3;
                b22 = C2 ^ ~C3 & C4;
                b32 = C3 ^ ~C4 & C0;
                b42 = C4 ^ ~C0 & C1;

                a40 ^= D4;
                C0 = ROL(a40, 27);
                a01 ^= D0;
                C1 = ROL(a01, 36);
                a12 ^= D1;
                C2 = ROL(a12, 10);
                a23 ^= D2;
                C3 = ROL(a23, 15);
                a34 ^= D3;
                C4 = ROL(a34, 56);

                b03 = C0 ^ ~C1 & C2;
                b13 = C1 ^ ~C2 & C3;
                b23 = C2 ^ ~C3 & C4;
                b33 = C3 ^ ~C4 & C0;
                b43 = C4 ^ ~C0 & C1;

                a20 ^= D2;
                C0 = ROL(a20, 62);
                a31 ^= D3;
                C1 = ROL(a31, 55);
                a42 ^= D4;
                C2 = ROL(a42, 39);
                a03 ^= D0;
                C3 = ROL(a03, 41);
                a14 ^= D1;
                C4 = ROL(a14, 2);
                b04 = C0 ^ ~C1 & C2;
                b14 = C1 ^ ~C2 & C3;
                b24 = C2 ^ ~C3 & C4;
                b34 = C3 ^ ~C4 & C0;
                b44 = C4 ^ ~C0 & C1;

                //    prepareTheta
                C0 = b00 ^ b01 ^ b02 ^ b03 ^ b04;
                C1 = b10 ^ b11 ^ b12 ^ b13 ^ b14;
                C2 = b20 ^ b21 ^ b22 ^ b23 ^ b24;
                C3 = b30 ^ b31 ^ b32 ^ b33 ^ b34;
                C4 = b40 ^ b41 ^ b42 ^ b43 ^ b44;

                //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
                D0 = C4 ^ ROL(C1, 1);
                D1 = C0 ^ ROL(C2, 1);
                D2 = C1 ^ ROL(C3, 1);
                D3 = C2 ^ ROL(C4, 1);
                D4 = C3 ^ ROL(C0, 1);

                b00 ^= D0;
                C0 = b00;
                b11 ^= D1;
                C1 = ROL(b11, 44);
                b22 ^= D2;
                C2 = ROL(b22, 43);
                b33 ^= D3;
                C3 = ROL(b33, 21);
                b44 ^= D4;
                C4 = ROL(b44, 14);
                a00 = C0 ^ ~C1 & C2;
                a00 ^= RoundConstants[round + 1];
                a10 = C1 ^ ~C2 & C3;
                a20 = C2 ^ ~C3 & C4;
                a30 = C3 ^ ~C4 & C0;
                a40 = C4 ^ ~C0 & C1;

                b30 ^= D3;
                C0 = ROL(b30, 28);
                b41 ^= D4;
                C1 = ROL(b41, 20);
                b02 ^= D0;
                C2 = ROL(b02, 3);
                b13 ^= D1;
                C3 = ROL(b13, 45);
                b24 ^= D2;
                C4 = ROL(b24, 61);
                a01 = C0 ^ ~C1 & C2;
                a11 = C1 ^ ~C2 & C3;
                a21 = C2 ^ ~C3 & C4;
                a31 = C3 ^ ~C4 & C0;
                a41 = C4 ^ ~C0 & C1;

                b10 ^= D1;
                C0 = ROL(b10, 1);
                b21 ^= D2;
                C1 = ROL(b21, 6);
                b32 ^= D3;
                C2 = ROL(b32, 25);
                b43 ^= D4;
                C3 = ROL(b43, 8);
                b04 ^= D0;
                C4 = ROL(b04, 18);
                a02 = C0 ^ ~C1 & C2;
                a12 = C1 ^ ~C2 & C3;
                a22 = C2 ^ ~C3 & C4;
                a32 = C3 ^ ~C4 & C0;
                a42 = C4 ^ ~C0 & C1;

                b40 ^= D4;
                C0 = ROL(b40, 27);
                b01 ^= D0;
                C1 = ROL(b01, 36);
                b12 ^= D1;
                C2 = ROL(b12, 10);
                b23 ^= D2;
                C3 = ROL(b23, 15);
                b34 ^= D3;
                C4 = ROL(b34, 56);
                a03 = C0 ^ ~C1 & C2;
                a13 = C1 ^ ~C2 & C3;
                a23 = C2 ^ ~C3 & C4;
                a33 = C3 ^ ~C4 & C0;
                a43 = C4 ^ ~C0 & C1;

                b20 ^= D2;
                C0 = ROL(b20, 62);
                b31 ^= D3;
                C1 = ROL(b31, 55);
                b42 ^= D4;
                C2 = ROL(b42, 39);
                b03 ^= D0;
                C3 = ROL(b03, 41);
                b14 ^= D1;
                C4 = ROL(b14, 2);
                a04 = C0 ^ ~C1 & C2;
                a14 = C1 ^ ~C2 & C3;
                a24 = C2 ^ ~C3 & C4;
                a34 = C3 ^ ~C4 & C0;
                a44 = C4 ^ ~C0 & C1;
            }

            //copyToState(state, A)
            st[0] = a00;
            st[1] = a10;
            st[2] = a20;
            st[3] = a30;
            st[4] = a40;
            st[5] = a01;
            st[6] = a11;
            st[7] = a21;
            st[8] = a31;
            st[9] = a41;
            st[10] = a02;
            st[11] = a12;
            st[12] = a22;
            st[13] = a32;
            st[14] = a42;
            st[15] = a03;
            st[16] = a13;
            st[17] = a23;
            st[18] = a33;
            st[19] = a43;
            st[20] = a04;
            st[21] = a14;
            st[22] = a24;
            st[23] = a34;
            st[24] = a44;
        }

        /// <summary>
        /// Computes the hash of a string using UTF8 encoding.
        /// </summary>
        /// <param name="utf8String">String to be converted to UTF8 bytes and hashed.</param>
        /// <returns></returns>
        public byte[] FromString(string utf8String)
        {
            var input = StringsRoot.Strings.UTF8.GetBytes(utf8String);
            var output = new byte[32];
            ComputeHash(input, output);
            return output;
        }

        /// <summary>
        /// Computes the hash of a string using given string encoding.
        /// For example <see cref="Encoding.ASCII"/>
        /// </summary>
        /// <param name="inputString">String to be converted to bytes and hashed.</param>
        /// <param name="stringEncoding">The string encoding to use. For example <see cref="Encoding.ASCII"/></param>
        /// <returns></returns>
        public byte[] FromString(string inputString, Encoding stringEncoding)
        {
            var input = stringEncoding.GetBytes(inputString);
            var output = new byte[32];
            ComputeHash(input, output);
            return output;
        }

        /// <summary>
        /// Decodes a hex string to bytes and computes the hash.
        /// </summary>
        /// <param name="hexString">The hex string to be decoded into bytes and hashed.</param>
        /// <returns></returns>
        public byte[] FromHex(string hexString)
        {
            var input = HexUtil.HexToBytes(hexString);
            var output = new byte[32];
            ComputeHash(input, output);
            return output;
        }

        public Span<byte> ComputeHash(Span<byte> input, int size = HASH_SIZE_InBytes)
        {
            Span<byte> output = new byte[size];
            ComputeHash(input, output);
            return output;
        }

        public byte[] ComputeHashBytes(Span<byte> input, int size = HASH_SIZE_InBytes)
        {
            var output = new byte[HASH_SIZE_InBytes];
            ComputeHash(input, output);
            return output;
        }




        /// <summary>
        /// Computes a Keccak 256 bit hash.
        /// </summary>
        /// <param name="input">A contiguous region of arbitrary memory with the bytes to hash.</param>
        /// <param name="output">A contiguous region of arbitrary memory that will be updated with the computed hash.</param>
        public void ComputeHash(Span<byte> input, Span<byte> output)
        {
            if (output.Length <= 0)
            {
                throw new ArgumentException("The length of the output buffer is less than or equal to zero.");
            }

            if (output.Length > State_Size_B_InBytes)
            {
                throw new ArgumentException("The output buffer is greater than the state B in bytes.");
            }

            byte[] stateArray = null;
            byte[] tempArray = null;

            try
            {
                stateArray = _arrayPool.Rent(State_Size_B_InBytes); // 200 bytes, or 1600 bits
                tempArray = _arrayPool.Rent(TEMP_BUFF_SIZE);

                var stateSpan = MemoryMarshal.Cast<byte, ulong>(stateArray.AsSpan(0, State_Size_B_InBytes));
                var tempSpan = tempArray.AsSpan(0, TEMP_BUFF_SIZE);

                stateSpan.Clear();
                tempSpan.Clear();

                int roundSize = State_Size_B_InBytes == output.Length ? HASH_DATA_AREA : State_Size_B_InBytes - 2 * output.Length;
                int roundSizeU64 = roundSize / 8;

                var inputLength = input.Length;
                int i;
                for (; inputLength >= roundSize; inputLength -= roundSize, input = input.Slice(roundSize))
                {
                    var input64 = MemoryMarshal.Cast<byte, ulong>(input);

                    for (i = 0; i < roundSizeU64; i++)
                    {
                        stateSpan[i] ^= input64[i];
                    }

                    KeccakF(stateSpan, ROUNDS);
                }

                // last block and padding
                if (inputLength >= TEMP_BUFF_SIZE || inputLength > roundSize || roundSize - inputLength + inputLength + 1 >= TEMP_BUFF_SIZE || roundSize == 0 || roundSize - 1 >= TEMP_BUFF_SIZE || roundSizeU64 * 8 > TEMP_BUFF_SIZE)
                {
                    throw new ArgumentException("Bad keccak use");
                }

                input.Slice(0, inputLength).CopyTo(tempSpan);
                tempSpan[inputLength++] = 1;
                tempSpan[roundSize - 1] |= 0x80;

                var tempU64 = MemoryMarshal.Cast<byte, ulong>(tempSpan);

                for (i = 0; i < roundSizeU64; i++)
                {
                    stateSpan[i] ^= tempU64[i];
                }

                KeccakF(stateSpan, ROUNDS);
                MemoryMarshal.AsBytes(stateSpan).Slice(0, output.Length).CopyTo(output);
            }
            finally
            {
                if (stateArray != null)
                {
                    _arrayPool.Return(stateArray);
                }

                if (tempArray != null)
                {
                    _arrayPool.Return(tempArray);
                }
            }
        }

        public void Keccak1600(Span<byte> input, Span<byte> output)
        {
            if (output.Length != State_Size_B_InBytes)
            {
                throw new ArgumentException($"Output length must be {State_Size_B_InBytes} bytes");
            }

            ComputeHash(input, output);
        }

        public void Update(Keccak256 keccak, byte[] array, int index, int size)
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
            if (keccak.State.Length == 0)
            {
                keccak.State = new ulong[Keccak256HashService.State_Size_B_InBytes / 8];
            }

            // If our remainder is non zero.
            int i;
            if (keccak.RemainderLength != 0)
            {
                // Copy data to our remainder
                var remainderAdditive = input.Slice(0, Math.Min(input.Length, keccak.RoundSize - keccak.RemainderLength));
                remainderAdditive.CopyTo(keccak.RemainderBuffer.Slice(keccak.RemainderLength).Span);

                // Increment the length
                keccak.RemainderLength += remainderAdditive.Length;

                // Increment the input
                input = input.Slice(remainderAdditive.Length);

                // If our remainder length equals a full round
                if (keccak.RemainderLength == keccak.RoundSize)
                {
                    // Cast our input to ulongs.
                    var remainderBufferU64 = MemoryMarshal.Cast<byte, ulong>(keccak.RemainderBuffer.Span);

                    // Loop for each ulong in this remainder, and xor the state with the input.
                    for (i = 0; i < keccak.RoundSizeU64; i++)
                    {
                        keccak.State.Span[i] ^= remainderBufferU64[i];
                    }

                    // Perform our keccakF on our state.
                    KeccakRoot.Keccak256.KeccakF(keccak.State.Span, ROUNDS);

                    // Clear remainder fields
                    keccak.RemainderLength = 0;
                    keccak.RemainderBuffer.Span.Clear();
                }
            }

            // Loop for every round in our size.
            while (input.Length >= keccak.RoundSize)
            {
                // Cast our input to ulongs.
                var input64 = MemoryMarshal.Cast<byte, ulong>(input);

                // Loop for each ulong in this round, and xor the state with the input.
                for (i = 0; i < keccak.RoundSizeU64; i++)
                {
                    keccak.State.Span[i] ^= input64[i];
                }

                // Perform our keccakF on our state.
                KeccakRoot.Keccak256.KeccakF(keccak.State.Span, ROUNDS);

                // Remove the input data processed this round.
                input = input.Slice(keccak.RoundSize);
            }

            // last block and padding
            if (input.Length >= TEMP_BUFF_SIZE || input.Length > keccak.RoundSize || keccak.RoundSize + 1 >= TEMP_BUFF_SIZE || keccak.RoundSize == 0 || keccak.RoundSize - 1 >= TEMP_BUFF_SIZE || keccak.RoundSizeU64 * 8 > TEMP_BUFF_SIZE)
            {
                throw new ArgumentException("Bad keccak use");
            }

            // If we have any remainder here, it means any remainder was processed before, we can copy our data over and set our length
            if (input.Length > 0)
            {
                input.CopyTo(keccak.RemainderBuffer.Span);
                keccak.RemainderLength = input.Length;
            }

            // Set the hash as null
            keccak._hash = null;
        }

        public byte[] UpdateFinal(Keccak256 keccak)
        {
            // Copy the remainder buffer
            Memory<byte> remainderClone = keccak.RemainderBuffer.ToArray();

            // Set a 1 byte after the remainder.
            remainderClone.Span[keccak.RemainderLength++] = 1;

            // Set the highest bit on the last byte.
            remainderClone.Span[keccak.RoundSize - 1] |= 0x80;

            // Cast the remainder buffer to ulongs.
            var temp64 = MemoryMarshal.Cast<byte, ulong>(remainderClone.Span);

            // Loop for each ulong in this round, and xor the state with the input.
            for (int i = 0; i < keccak.RoundSizeU64; i++)
            {
                keccak.State.Span[i] ^= temp64[i];
            }

            KeccakRoot.Keccak256.KeccakF(keccak.State.Span, ROUNDS);

            // Obtain the state data in the desired (hash) size we want.
            keccak._hash = MemoryMarshal.AsBytes(keccak.State.Span).Slice(0, keccak.HashSize).ToArray();

            // Return the result.
            return keccak.Hash;
        }

        public void Reset(Keccak256 keccak)
        {
            // Clear our hash state information.
            keccak.State.Span.Clear();
            keccak.RemainderBuffer.Span.Clear();
            keccak.RemainderLength = 0;
            keccak._hash = null;
        }
    }
}
