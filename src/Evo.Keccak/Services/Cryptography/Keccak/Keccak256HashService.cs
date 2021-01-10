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

            ulong e04, e14, e24, e34, e44;
            ulong e03, e13, e23, e33, e43;
            ulong e02, e12, e22, e32, e42;
            ulong e01, e11, e21, e31, e41;
            ulong e00, e10, e20, e30, e40;

            ulong G0, G1, G2, G3, G4;
            ulong H0, H1, H2, H3, H4;

            ulong b04, b14, b24, b34, b44;
            ulong b03, b13, b23, b33, b43;
            ulong b02, b12, b22, b32, b42;
            ulong b01, b11, b21, b31, b41;
            ulong b00, b10, b20, b30, b40;

            //copyFromState(A, state)
            e00 = st[0];
            e10 = st[1];
            e20 = st[2];
            e30 = st[3];
            e40 = st[4];
            e01 = st[5];
            e11 = st[6];
            e21 = st[7];
            e31 = st[8];
            e41 = st[9];
            e02 = st[10];
            e12 = st[11];
            e22 = st[12];
            e32 = st[13];
            e42 = st[14];
            e03 = st[15];
            e13 = st[16];
            e23 = st[17];
            e33 = st[18];
            e43 = st[19];
            e04 = st[20];
            e14 = st[21];
            e24 = st[22];
            e34 = st[23];
            e44 = st[24];

            for (var round = 0; round < rounds; round += 2)
            {
                //    prepareTheta
                G0 = e00 ^ e01 ^ e02 ^ e03 ^ e04;
                G1 = e10 ^ e11 ^ e12 ^ e13 ^ e14;
                G2 = e20 ^ e21 ^ e22 ^ e23 ^ e24;
                G3 = e30 ^ e31 ^ e32 ^ e33 ^ e34;
                G4 = e40 ^ e41 ^ e42 ^ e43 ^ e44;

                //thetaRhoPiChiIotaPrepareTheta(round  , A, E)
                H0 = G4 ^ ROL(G1, 1);
                H1 = G0 ^ ROL(G2, 1);
                H2 = G1 ^ ROL(G3, 1);
                H3 = G2 ^ ROL(G4, 1);
                H4 = G3 ^ ROL(G0, 1);

                e00 ^= H0;
                G0 = e00;
                e11 ^= H1;
                G1 = ROL(e11, 44);
                e22 ^= H2;
                G2 = ROL(e22, 43);
                e33 ^= H3;
                G3 = ROL(e33, 21);
                e44 ^= H4;
                G4 = ROL(e44, 14);

                b00 = G0 ^ ~G1 & G2;
                b00 ^= RoundConstants[round];
                b10 = G1 ^ ~G2 & G3;
                b20 = G2 ^ ~G3 & G4;
                b30 = G3 ^ ~G4 & G0;
                b40 = G4 ^ ~G0 & G1;

                e30 ^= H3;
                G0 = ROL(e30, 28);
                e41 ^= H4;
                G1 = ROL(e41, 20);
                e02 ^= H0;
                G2 = ROL(e02, 3);
                e13 ^= H1;
                G3 = ROL(e13, 45);
                e24 ^= H2;
                G4 = ROL(e24, 61);
                b01 = G0 ^ ~G1 & G2;
                b11 = G1 ^ ~G2 & G3;
                b21 = G2 ^ ~G3 & G4;
                b31 = G3 ^ ~G4 & G0;
                b41 = G4 ^ ~G0 & G1;

                e10 ^= H1;
                G0 = ROL(e10, 1);
                e21 ^= H2;
                G1 = ROL(e21, 6);
                e32 ^= H3;
                G2 = ROL(e32, 25);
                e43 ^= H4;
                G3 = ROL(e43, 8);
                e04 ^= H0;
                G4 = ROL(e04, 18);
                b02 = G0 ^ ~G1 & G2;
                b12 = G1 ^ ~G2 & G3;
                b22 = G2 ^ ~G3 & G4;
                b32 = G3 ^ ~G4 & G0;
                b42 = G4 ^ ~G0 & G1;

                e40 ^= H4;
                G0 = ROL(e40, 27);
                e01 ^= H0;
                G1 = ROL(e01, 36);
                e12 ^= H1;
                G2 = ROL(e12, 10);
                e23 ^= H2;
                G3 = ROL(e23, 15);
                e34 ^= H3;
                G4 = ROL(e34, 56);

                b03 = G0 ^ ~G1 & G2;
                b13 = G1 ^ ~G2 & G3;
                b23 = G2 ^ ~G3 & G4;
                b33 = G3 ^ ~G4 & G0;
                b43 = G4 ^ ~G0 & G1;

                e20 ^= H2;
                G0 = ROL(e20, 62);
                e31 ^= H3;
                G1 = ROL(e31, 55);
                e42 ^= H4;
                G2 = ROL(e42, 39);
                e03 ^= H0;
                G3 = ROL(e03, 41);
                e14 ^= H1;
                G4 = ROL(e14, 2);
                b04 = G0 ^ ~G1 & G2;
                b14 = G1 ^ ~G2 & G3;
                b24 = G2 ^ ~G3 & G4;
                b34 = G3 ^ ~G4 & G0;
                b44 = G4 ^ ~G0 & G1;

                //    prepareTheta
                G0 = b00 ^ b01 ^ b02 ^ b03 ^ b04;
                G1 = b10 ^ b11 ^ b12 ^ b13 ^ b14;
                G2 = b20 ^ b21 ^ b22 ^ b23 ^ b24;
                G3 = b30 ^ b31 ^ b32 ^ b33 ^ b34;
                G4 = b40 ^ b41 ^ b42 ^ b43 ^ b44;

                //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
                H0 = G4 ^ ROL(G1, 1);
                H1 = G0 ^ ROL(G2, 1);
                H2 = G1 ^ ROL(G3, 1);
                H3 = G2 ^ ROL(G4, 1);
                H4 = G3 ^ ROL(G0, 1);

                b00 ^= H0;
                G0 = b00;
                b11 ^= H1;
                G1 = ROL(b11, 44);
                b22 ^= H2;
                G2 = ROL(b22, 43);
                b33 ^= H3;
                G3 = ROL(b33, 21);
                b44 ^= H4;
                G4 = ROL(b44, 14);
                e00 = G0 ^ ~G1 & G2;
                e00 ^= RoundConstants[round + 1];
                e10 = G1 ^ ~G2 & G3;
                e20 = G2 ^ ~G3 & G4;
                e30 = G3 ^ ~G4 & G0;
                e40 = G4 ^ ~G0 & G1;

                b30 ^= H3;
                G0 = ROL(b30, 28);
                b41 ^= H4;
                G1 = ROL(b41, 20);
                b02 ^= H0;
                G2 = ROL(b02, 3);
                b13 ^= H1;
                G3 = ROL(b13, 45);
                b24 ^= H2;
                G4 = ROL(b24, 61);
                e01 = G0 ^ ~G1 & G2;
                e11 = G1 ^ ~G2 & G3;
                e21 = G2 ^ ~G3 & G4;
                e31 = G3 ^ ~G4 & G0;
                e41 = G4 ^ ~G0 & G1;

                b10 ^= H1;
                G0 = ROL(b10, 1);
                b21 ^= H2;
                G1 = ROL(b21, 6);
                b32 ^= H3;
                G2 = ROL(b32, 25);
                b43 ^= H4;
                G3 = ROL(b43, 8);
                b04 ^= H0;
                G4 = ROL(b04, 18);
                e02 = G0 ^ ~G1 & G2;
                e12 = G1 ^ ~G2 & G3;
                e22 = G2 ^ ~G3 & G4;
                e32 = G3 ^ ~G4 & G0;
                e42 = G4 ^ ~G0 & G1;

                b40 ^= H4;
                G0 = ROL(b40, 27);
                b01 ^= H0;
                G1 = ROL(b01, 36);
                b12 ^= H1;
                G2 = ROL(b12, 10);
                b23 ^= H2;
                G3 = ROL(b23, 15);
                b34 ^= H3;
                G4 = ROL(b34, 56);
                e03 = G0 ^ ~G1 & G2;
                e13 = G1 ^ ~G2 & G3;
                e23 = G2 ^ ~G3 & G4;
                e33 = G3 ^ ~G4 & G0;
                e43 = G4 ^ ~G0 & G1;

                b20 ^= H2;
                G0 = ROL(b20, 62);
                b31 ^= H3;
                G1 = ROL(b31, 55);
                b42 ^= H4;
                G2 = ROL(b42, 39);
                b03 ^= H0;
                G3 = ROL(b03, 41);
                b14 ^= H1;
                G4 = ROL(b14, 2);
                e04 = G0 ^ ~G1 & G2;
                e14 = G1 ^ ~G2 & G3;
                e24 = G2 ^ ~G3 & G4;
                e34 = G3 ^ ~G4 & G0;
                e44 = G4 ^ ~G0 & G1;
            }

            //copyToState(state, A)
            st[0] = e00;
            st[1] = e10;
            st[2] = e20;
            st[3] = e30;
            st[4] = e40;
            st[5] = e01;
            st[6] = e11;
            st[7] = e21;
            st[8] = e31;
            st[9] = e41;
            st[10] = e02;
            st[11] = e12;
            st[12] = e22;
            st[13] = e32;
            st[14] = e42;
            st[15] = e03;
            st[16] = e13;
            st[17] = e23;
            st[18] = e33;
            st[19] = e43;
            st[20] = e04;
            st[21] = e14;
            st[22] = e24;
            st[23] = e34;
            st[24] = e44;
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
