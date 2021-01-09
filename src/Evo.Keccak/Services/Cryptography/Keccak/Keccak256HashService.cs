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

            ulong e04, e14, e24, e34, e44;
            ulong e03, eme, emi, emo, emu;
            ulong e02, eke, eki, eko, eku;
            ulong e01, ege, egi, ego, egu;
            ulong e00, e10, e20, e30, e40;

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

                e00 = C0 ^ ~C1 & C2;
                e00 ^= RoundConstants[round];
                e10 = C1 ^ ~C2 & C3;
                e20 = C2 ^ ~C3 & C4;
                e30 = C3 ^ ~C4 & C0;
                e40 = C4 ^ ~C0 & C1;

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
                e01 = C0 ^ ~C1 & C2;
                ege = C1 ^ ~C2 & C3;
                egi = C2 ^ ~C3 & C4;
                ego = C3 ^ ~C4 & C0;
                egu = C4 ^ ~C0 & C1;

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
                e02 = C0 ^ ~C1 & C2;
                eke = C1 ^ ~C2 & C3;
                eki = C2 ^ ~C3 & C4;
                eko = C3 ^ ~C4 & C0;
                eku = C4 ^ ~C0 & C1;

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

                e03 = C0 ^ ~C1 & C2;
                eme = C1 ^ ~C2 & C3;
                emi = C2 ^ ~C3 & C4;
                emo = C3 ^ ~C4 & C0;
                emu = C4 ^ ~C0 & C1;

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
                e04 = C0 ^ ~C1 & C2;
                e14 = C1 ^ ~C2 & C3;
                e24 = C2 ^ ~C3 & C4;
                e34 = C3 ^ ~C4 & C0;
                e44 = C4 ^ ~C0 & C1;

                //    prepareTheta
                C0 = e00 ^ e01 ^ e02 ^ e03 ^ e04;
                C1 = e10 ^ ege ^ eke ^ eme ^ e14;
                C2 = e20 ^ egi ^ eki ^ emi ^ e24;
                C3 = e30 ^ ego ^ eko ^ emo ^ e34;
                C4 = e40 ^ egu ^ eku ^ emu ^ e44;

                //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
                D0 = C4 ^ ROL(C1, 1);
                D1 = C0 ^ ROL(C2, 1);
                D2 = C1 ^ ROL(C3, 1);
                D3 = C2 ^ ROL(C4, 1);
                D4 = C3 ^ ROL(C0, 1);

                e00 ^= D0;
                C0 = e00;
                ege ^= D1;
                C1 = ROL(ege, 44);
                eki ^= D2;
                C2 = ROL(eki, 43);
                emo ^= D3;
                C3 = ROL(emo, 21);
                e44 ^= D4;
                C4 = ROL(e44, 14);
                a00 = C0 ^ ~C1 & C2;
                a00 ^= RoundConstants[round + 1];
                a10 = C1 ^ ~C2 & C3;
                a20 = C2 ^ ~C3 & C4;
                a30 = C3 ^ ~C4 & C0;
                a40 = C4 ^ ~C0 & C1;

                e30 ^= D3;
                C0 = ROL(e30, 28);
                egu ^= D4;
                C1 = ROL(egu, 20);
                e02 ^= D0;
                C2 = ROL(e02, 3);
                eme ^= D1;
                C3 = ROL(eme, 45);
                e24 ^= D2;
                C4 = ROL(e24, 61);
                a01 = C0 ^ ~C1 & C2;
                a11 = C1 ^ ~C2 & C3;
                a21 = C2 ^ ~C3 & C4;
                a31 = C3 ^ ~C4 & C0;
                a41 = C4 ^ ~C0 & C1;

                e10 ^= D1;
                C0 = ROL(e10, 1);
                egi ^= D2;
                C1 = ROL(egi, 6);
                eko ^= D3;
                C2 = ROL(eko, 25);
                emu ^= D4;
                C3 = ROL(emu, 8);
                e04 ^= D0;
                C4 = ROL(e04, 18);
                a02 = C0 ^ ~C1 & C2;
                a12 = C1 ^ ~C2 & C3;
                a22 = C2 ^ ~C3 & C4;
                a32 = C3 ^ ~C4 & C0;
                a42 = C4 ^ ~C0 & C1;

                e40 ^= D4;
                C0 = ROL(e40, 27);
                e01 ^= D0;
                C1 = ROL(e01, 36);
                eke ^= D1;
                C2 = ROL(eke, 10);
                emi ^= D2;
                C3 = ROL(emi, 15);
                e34 ^= D3;
                C4 = ROL(e34, 56);
                a03 = C0 ^ ~C1 & C2;
                a13 = C1 ^ ~C2 & C3;
                a23 = C2 ^ ~C3 & C4;
                a33 = C3 ^ ~C4 & C0;
                a43 = C4 ^ ~C0 & C1;

                e20 ^= D2;
                C0 = ROL(e20, 62);
                ego ^= D3;
                C1 = ROL(ego, 55);
                eku ^= D4;
                C2 = ROL(eku, 39);
                e03 ^= D0;
                C3 = ROL(e03, 41);
                e14 ^= D1;
                C4 = ROL(e14, 2);
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
            if (output.Length <= 0 || output.Length > State_Size_B_InBytes)
            {
                throw new ArgumentException("Bad keccak use");
            }

            byte[] stateArray = _arrayPool.Rent(State_Size_B_InBytes);
            byte[] tempArray = _arrayPool.Rent(TEMP_BUFF_SIZE);

            try
            {
                Span<ulong> state = MemoryMarshal.Cast<byte, ulong>(stateArray.AsSpan(0, State_Size_B_InBytes));
                Span<byte> temp = tempArray.AsSpan(0, TEMP_BUFF_SIZE);

                state.Clear();
                temp.Clear();

                int roundSize = State_Size_B_InBytes == output.Length ? HASH_DATA_AREA : State_Size_B_InBytes - 2 * output.Length;
                int roundSizeU64 = roundSize / 8;

                var inputLength = input.Length;
                int i;
                for (; inputLength >= roundSize; inputLength -= roundSize, input = input.Slice(roundSize))
                {
                    var input64 = MemoryMarshal.Cast<byte, ulong>(input);

                    for (i = 0; i < roundSizeU64; i++)
                    {
                        state[i] ^= input64[i];
                    }

                    KeccakF(state, ROUNDS);
                }

                // last block and padding
                if (inputLength >= TEMP_BUFF_SIZE || inputLength > roundSize || roundSize - inputLength + inputLength + 1 >= TEMP_BUFF_SIZE || roundSize == 0 || roundSize - 1 >= TEMP_BUFF_SIZE || roundSizeU64 * 8 > TEMP_BUFF_SIZE)
                {
                    throw new ArgumentException("Bad keccak use");
                }

                input.Slice(0, inputLength).CopyTo(temp);
                temp[inputLength++] = 1;
                temp[roundSize - 1] |= 0x80;

                var tempU64 = MemoryMarshal.Cast<byte, ulong>(temp);

                for (i = 0; i < roundSizeU64; i++)
                {
                    state[i] ^= tempU64[i];
                }

                KeccakF(state, ROUNDS);
                MemoryMarshal.AsBytes(state).Slice(0, output.Length).CopyTo(output);
            }
            finally
            {
                _arrayPool.Return(stateArray);
                _arrayPool.Return(tempArray);
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
