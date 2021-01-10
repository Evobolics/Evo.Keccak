using Evo.Keccak;
using Evo.Statics;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Evo.Services.Cryptography.Keccak
{
    public class Keccak1600Service_Teaching1
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

        //----- b -----/----- r ----- /----- c -----/-- security --/---- hash ----/ -- rounds -- /--- l ---/ 
        // state bits  /  rate bits   /    bits     /    level     /  output bits / r = 12 + 2*l /     
        //   1600      /     1152     /     448     /     112      /     224      /      24      /    6    /
        //   1600      /     1088     /     512     /     128      /     256      /      24      /    6    / 
        //   1600      /     832      /     768     /     192      /     384      /      24      /    6    / 
        //   1600      /     576      /     1024    /     256      /     512      /      24      /    6    / 

        public const int LaneWidth_W = 2 ^ 6; // 2 * l where l = 6, LaneSize = 64
        public const int Rounds = 12 + 2 * 6; // Rounds = 24 = 12 + 2 * 1, where l = 6 

        static readonly ArrayPool<byte> _arrayPool = ArrayPool<byte>.Shared;

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

                    KeccakF(stateSpan, LANE_BITS);
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

                KeccakF(stateSpan, LANE_BITS);
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

        // --------------------------------------------
        // --------------------------------------------
        //       ALGORITHMIC STEPS - 1 through 5
        // --------------------------------------------
        // --------------------------------------------

        // Step 1. - Theta - θ

        // NOTE: The order of the remaining four steps does not matter, just as long as theta is done first.

        // Step 2. - Rho   - ρ 
        // Step 3. - Pi    - π
        // Step 4. - Chi   - χ
        // Step 5. - Iota  - ι



        /// <summary>
        /// Step 1 - Theta
        /// </summary>
        /// <param name="A">
        /// The state A containing 25 ulong words.  For the keccak-f[1600] implmenetation, all 64 bits
        /// of each ulong will be operated upon.
        /// </param>
        public void KeccakF(Span<ulong> A, int laneWidth_W)
        {
            // Matrix of 'A' LANES of bits, w bits long, with w = 64 for keccak-f[64].
            // The x direction going to the right, y incresing vertically, and with z 
            // dirction going into the page away from reader.  
            //
            // 0,4 // 1,4 // 2,4 // 3,4 // 4,4 //     // ^
            // 0,3 // 1,3 // 2,3 // 3,3 // 4,4 //     // |    ^
            // 0,2 // 1,2 // 2,2 // 3,2 // 4,2 //     // y   /
            // 0,1 // 1,1 // 2,1 // 3,1 // 4,1 //     //    z
            // 0,0 // 1,0 // 2,0 // 3,0 // 4,0 //     // (0,0,0) x -> 

            // ------------------------------
            // DECLARE VARIABLES - NOTE: Same variables can be used for keccak-f[25, 50, 100, 200, 400, 800, and 1600]
            // ------------------------------

            // Variables needed for the THETA (θ) Step
            // ---------------------------------------

            // In a[x, y] coordinates, where x increases to the right and y vertically upwards
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

            // Map the single dimensional array of 25 words into individual variables for speed reasons.
            a00 = A[0];
            a10 = A[1];
            a20 = A[2];
            a30 = A[3];
            a40 = A[4];
            a01 = A[5];
            a11 = A[6];
            a21 = A[7];
            a31 = A[8];
            a41 = A[9];
            a02 = A[10];
            a12 = A[11];
            a22 = A[12];
            a32 = A[13];
            a42 = A[14];
            a03 = A[15];
            a13 = A[16];
            a23 = A[17];
            a33 = A[18];
            a43 = A[19];
            a04 = A[20];
            a14 = A[21];
            a24 = A[22];
            a34 = A[23];
            a44 = A[24];

            for (int round = 0; round < 24; round += 2)
            {

                // -------------------------------------------
                // STEP 1 - THETA (θ) Step, with input A[x,y] where x, y ranges from 1 to 4.
                // -------------------------------------------
                //
                // OVERVIEW
                //---------
                // θ - step a:  C[x]    = A[x, 0] ⊕ A[x, 1] ⊕ A[x, 2] ⊕ A[x, 3] ⊕ A[x, 4] for x =    0,1,2,3,4
                //
                //    Explanation:   Take 5 lanes and xor them together to form a single lane
                //
                //        Example:   C0 = a00 ^ a01 ^ a02 ^ a03 ^ a04;     

                // θ - step b:  D[x]    = C[x−1]  ⊕ rot(C[x + 1], 1)                      for x =    0,1,2,3,4
                //
                //    Explanation:   Take the virtual lane C[x] and xor it with the same virtual lane rotated by a single bit
                //                   If C[x-1] causes a negative index, then it wraps around.
                //
                // θ - step c:  A[x, y] = A[x, y] ⊕ D[x]                                  for x, y = 0,1,2,3,4
                //      OR 
                // θ - step c.0:  A[x, 0] = A[x, 0] ⊕ D[x]
                // θ - step c.1:  A[x, 1] = A[x, 1] ⊕ D[x]
                // θ - step c.2:  A[x, 2] = A[x, 2] ⊕ D[x]
                // θ - step c.3:  A[x, 3] = A[x, 3] ⊕ D[x]
                // θ - step c.4:  A[x, 4] = A[x, 4] ⊕ D[x]
                //    Explanation:   Take the virtual lane D[x] and xor it with each veritical stack of lanes
                // 
                // Algorithm Details:
                //
                // 1.  C[x] is one-dimensional array which contain five words (integers) of length w bits, for this implementation, w is 64
                // 2.  D[x] is one-dimensional array which contain five words (integers) of length w bits, for this implementation, w is 64
                // 3.  The ⊕ symbol denotes a bit-wise XOR operation of the two w-bit operands
                // 4.  The rot(C[],1) function denotes a rotation of the operand by one bit in the z direction, i.e. the lane will be shifted
                // 5. 

                //--------------------------------------------------------------------------------------------
                // θ - step a:  C[x]    = A[x, 0] ⊕ A[x, 1] ⊕ A[x, 2] ⊕ A[x, 3] ⊕ A[x, 4] for x =    0,1,2,3,4
                //--------------------------------------------------------------------------------------------
                //    Explanation:   Take 5 lanes and xor them together to form a single lane
                //
                //        Example:   C0 = a00 ^ a01 ^ a02 ^ a03 ^ a04;   

                // θ - step a.0: Compute column C[0] of rows: 
                //
                //   Take first vertical slice of lanes, all in same x=0 column, and xors them together
                //   to form a single virtual lane, called c0.

                C0 = a00 ^ a01 ^ a02 ^ a03 ^ a04;

                // θ - step a.1: Compute column C[1] of rows: 
                //
                //   Take first vertical slice of lanes, all in same x=1 column, and xors them together
                //   to form a single virtual lane, called c1.

                C1 = a10 ^ a11 ^ a12 ^ a13 ^ a14;

                // θ - step a.2: Compute column C[2] of rows: 
                //
                //   Take first vertical slice of lanes, all in same x=2 column, and xors them together
                //   to form a single virtual lane, called c2.

                C2 = a20 ^ a21 ^ a22 ^ a23 ^ a24;

                // θ - step a.3: Compute column C[3] of rows: 
                //
                //   Take first vertical slice of lanes, all in same x=3 column, and xors them together
                //   to form a single virtual lane, called c3.

                C3 = a30 ^ a31 ^ a32 ^ a33 ^ a34;

                // θ - step a.4: Compute column C[4] of rows: 
                //
                //   Take first vertical slice of lanes, all in same x=4 column, and xors them together
                //   to form a single virtual lane, called c4.

                C4 = a40 ^ a41 ^ a42 ^ a43 ^ a44;

                // θ - step b.0-4:  D[x]    = C[x−1]  ⊕ rot(C[x + 1], 1)                      for x =    0,1,2,3,4
                //
                //    Explanation:   Take the virtual lane C[x] and xor it with the same virtual lane rotated by a single bit
                //                   If C[x-1] causes a negative index, then it wraps around.
                //
                D0 = C4 ^ RotateLaneByXBits(C1, 1, laneWidth_W); // C[x-1] ^ RotateLaneByXBits(C[x + 1], 1, LaneWidth_W), x = 0 (remember it wraps)
                D1 = C0 ^ RotateLaneByXBits(C2, 1, laneWidth_W); // C[x-1] ^ RotateLaneByXBits(C[x + 1], 1, LaneWidth_W), x = 1 
                D2 = C1 ^ RotateLaneByXBits(C3, 1, laneWidth_W); // C[x-1] ^ RotateLaneByXBits(C[x + 1], 1, LaneWidth_W), x = 2 
                D3 = C2 ^ RotateLaneByXBits(C4, 1, laneWidth_W); // C[x-1] ^ RotateLaneByXBits(C[x + 1], 1, LaneWidth_W), x = 3 
                D4 = C3 ^ RotateLaneByXBits(C0, 1, laneWidth_W); // C[x-1] ^ RotateLaneByXBits(C[x + 1], 1, LaneWidth_W), x = 4 (remember it wraps)


                // θ - step c:  A[x, y] = A[x, y] ⊕ D[x]                                  for x, y = 0,1,2,3,4
                //    Explanation:   Take the virtual lane D[x] and xor it with each veritical stack of lanes

                // θ - step c.0:  A[x, 0] = A[x, 0] ⊕ D[x]
                a00 ^= D0;
                a01 ^= D0;
                a02 ^= D0;
                a03 ^= D0;
                a04 ^= D0;

                // θ - step c.1:  A[x, 1] = A[x, 1] ⊕ D[x]
                a10 ^= D1;
                a11 ^= D1;
                a12 ^= D1;
                a13 ^= D1;
                a14 ^= D1;

                // θ - step c.2:  A[x, 2] = A[x, 2] ⊕ D[x]
                a20 ^= D2;
                a21 ^= D2;
                a22 ^= D2;
                a23 ^= D2;
                a24 ^= D2;

                // θ - step c.3:  A[x, 3] = A[x, 3] ⊕ D[x]
                a30 ^= D3;
                a31 ^= D3;
                a32 ^= D3;
                a33 ^= D3;
                a34 ^= D3;

                // θ - step c.4:  A[x, 4] = A[x, 4] ⊕ D[x]
                a40 ^= D4;
                a41 ^= D4;
                a42 ^= D4;
                a43 ^= D4;
                a44 ^= D4;


                C0 = a00;  // position not rotated
                C1 = RotateLaneByXBits(a11, 44, laneWidth_W);
                C2 = RotateLaneByXBits(a22, 43, laneWidth_W);
                C3 = RotateLaneByXBits(a33, 21, laneWidth_W);
                C4 = RotateLaneByXBits(a44, 14, laneWidth_W);

                b00 = C0 ^ ~C1 & C2;
                b00 ^= KeccakServiceBase.RoundConstants[round];
                b10 = C1 ^ ~C2 & C3;
                b20 = C2 ^ ~C3 & C4;
                b30 = C3 ^ ~C4 & C0;
                b40 = C4 ^ ~C0 & C1;

                C0 = RotateLaneByXBits(a30, 28, laneWidth_W);
                C1 = RotateLaneByXBits(a41, 20, laneWidth_W);
                C2 = RotateLaneByXBits(a02, 3, laneWidth_W);
                C3 = RotateLaneByXBits(a13, 45, laneWidth_W);
                C4 = RotateLaneByXBits(a24, 61, laneWidth_W);

                b01 = C0 ^ ~C1 & C2;
                b11 = C1 ^ ~C2 & C3;
                b21 = C2 ^ ~C3 & C4;
                b31 = C3 ^ ~C4 & C0;
                b41 = C4 ^ ~C0 & C1;

                C0 = RotateLaneByXBits(a10, 1, laneWidth_W);
                C1 = RotateLaneByXBits(a21, 6, laneWidth_W);
                C2 = RotateLaneByXBits(a32, 25, laneWidth_W);
                C3 = RotateLaneByXBits(a43, 8, laneWidth_W);
                C4 = RotateLaneByXBits(a04, 18, laneWidth_W);

                b02 = C0 ^ ~C1 & C2;
                b12 = C1 ^ ~C2 & C3;
                b22 = C2 ^ ~C3 & C4;
                b32 = C3 ^ ~C4 & C0;
                b42 = C4 ^ ~C0 & C1;

                C0 = RotateLaneByXBits(a40, 27, laneWidth_W);
                C1 = RotateLaneByXBits(a01, 36, laneWidth_W);
                C2 = RotateLaneByXBits(a12, 10, laneWidth_W);
                C3 = RotateLaneByXBits(a23, 15, laneWidth_W);
                C4 = RotateLaneByXBits(a34, 56, laneWidth_W);

                b03 = C0 ^ ~C1 & C2;
                b13 = C1 ^ ~C2 & C3;
                b23 = C2 ^ ~C3 & C4;
                b33 = C3 ^ ~C4 & C0;
                b43 = C4 ^ ~C0 & C1;

                C0 = RotateLaneByXBits(a20, 62, laneWidth_W);
                C1 = RotateLaneByXBits(a31, 55, laneWidth_W);
                C2 = RotateLaneByXBits(a42, 39, laneWidth_W);
                C3 = RotateLaneByXBits(a03, 41, laneWidth_W);
                C4 = RotateLaneByXBits(a14, 2, laneWidth_W);

                b04 = C0 ^ ~C1 & C2;
                b14 = C1 ^ ~C2 & C3;
                b24 = C2 ^ ~C3 & C4;
                b34 = C3 ^ ~C4 & C0;
                b44 = C4 ^ ~C0 & C1;

                C0 = b00 ^ b01 ^ b02 ^ b03 ^ b04;
                C1 = b10 ^ b11 ^ b12 ^ b13 ^ b14;
                C2 = b20 ^ b21 ^ b22 ^ b23 ^ b24;
                C3 = b30 ^ b31 ^ b32 ^ b33 ^ b34;
                C4 = b40 ^ b41 ^ b42 ^ b43 ^ b44;

                D0 = C4 ^ RotateLaneByXBits(C1, 1, laneWidth_W); // C[x-1] ^ RotateLaneByXBits(C[x + 1], 1, LaneWidth_W), x = 0 (remember it wraps)
                D1 = C0 ^ RotateLaneByXBits(C2, 1, laneWidth_W); // C[x-1] ^ RotateLaneByXBits(C[x + 1], 1, LaneWidth_W), x = 1 
                D2 = C1 ^ RotateLaneByXBits(C3, 1, laneWidth_W); // C[x-1] ^ RotateLaneByXBits(C[x + 1], 1, LaneWidth_W), x = 2 
                D3 = C2 ^ RotateLaneByXBits(C4, 1, laneWidth_W); // C[x-1] ^ RotateLaneByXBits(C[x + 1], 1, LaneWidth_W), x = 3 
                D4 = C3 ^ RotateLaneByXBits(C0, 1, laneWidth_W); // C[x-1] ^ RotateLaneByXBits(C[x + 1], 1, LaneWidth_W), x = 4 (remember it wraps)

               
                b00 ^= D0;
                b01 ^= D0;
                b02 ^= D0;
                b03 ^= D0;
                b04 ^= D0;

                
                b10 ^= D1;
                b11 ^= D1;
                b12 ^= D1;
                b13 ^= D1;
                b14 ^= D1;

                
                b20 ^= D2;
                b21 ^= D2;
                b22 ^= D2;
                b23 ^= D2;
                b24 ^= D2;

                
                b30 ^= D3;
                b31 ^= D3;
                b32 ^= D3;
                b33 ^= D3;
                b34 ^= D3;

                
                b40 ^= D4;
                b41 ^= D4;
                b42 ^= D4;
                b43 ^= D4;
                b44 ^= D4;

                C0 = b00;  // position not rotated
                C1 = RotateLaneByXBits(b11, 44, laneWidth_W);
                C2 = RotateLaneByXBits(b22, 43, laneWidth_W);
                C3 = RotateLaneByXBits(b33, 21, laneWidth_W);
                C4 = RotateLaneByXBits(b44, 14, laneWidth_W);

                a00 = C0 ^ ~C1 & C2;
                a00 ^= KeccakServiceBase.RoundConstants[round+1];
                a10 = C1 ^ ~C2 & C3;
                a20 = C2 ^ ~C3 & C4;
                a30 = C3 ^ ~C4 & C0;
                a40 = C4 ^ ~C0 & C1;

                C0 = RotateLaneByXBits(b30, 28, laneWidth_W);
                C1 = RotateLaneByXBits(b41, 20, laneWidth_W);
                C2 = RotateLaneByXBits(b02, 3, laneWidth_W);
                C3 = RotateLaneByXBits(b13, 45, laneWidth_W);
                C4 = RotateLaneByXBits(b24, 61, laneWidth_W);

                a01 = C0 ^ ~C1 & C2;
                a11 = C1 ^ ~C2 & C3;
                a21 = C2 ^ ~C3 & C4;
                a31 = C3 ^ ~C4 & C0;
                a41 = C4 ^ ~C0 & C1;

                C0 = RotateLaneByXBits(b10, 1, laneWidth_W);
                C1 = RotateLaneByXBits(b21, 6, laneWidth_W);
                C2 = RotateLaneByXBits(b32, 25, laneWidth_W);
                C3 = RotateLaneByXBits(b43, 8, laneWidth_W);
                C4 = RotateLaneByXBits(b04, 18, laneWidth_W);

                a02 = C0 ^ ~C1 & C2;
                a12 = C1 ^ ~C2 & C3;
                a22 = C2 ^ ~C3 & C4;
                a32 = C3 ^ ~C4 & C0;
                a42 = C4 ^ ~C0 & C1;

                C0 = RotateLaneByXBits(b40, 27, laneWidth_W);
                C1 = RotateLaneByXBits(b01, 36, laneWidth_W);
                C2 = RotateLaneByXBits(b12, 10, laneWidth_W);
                C3 = RotateLaneByXBits(b23, 15, laneWidth_W);
                C4 = RotateLaneByXBits(b34, 56, laneWidth_W);

                a03 = C0 ^ ~C1 & C2;
                a13 = C1 ^ ~C2 & C3;
                a23 = C2 ^ ~C3 & C4;
                a33 = C3 ^ ~C4 & C0;
                a43 = C4 ^ ~C0 & C1;

                C0 = RotateLaneByXBits(b20, 62, laneWidth_W);
                C1 = RotateLaneByXBits(b31, 55, laneWidth_W);
                C2 = RotateLaneByXBits(b42, 39, laneWidth_W);
                C3 = RotateLaneByXBits(b03, 41, laneWidth_W);
                C4 = RotateLaneByXBits(b14, 2, laneWidth_W);

                a04 = C0 ^ ~C1 & C2;
                a14 = C1 ^ ~C2 & C3;
                a24 = C2 ^ ~C3 & C4;
                a34 = C3 ^ ~C4 & C0;
                a44 = C4 ^ ~C0 & C1;
            }

            //copyToState(state, A)
            A[0] = a00;
            A[1] = a10;
            A[2] = a20;
            A[3] = a30;
            A[4] = a40;
            A[5] = a01;
            A[6] = a11;
            A[7] = a21;
            A[8] = a31;
            A[9] = a41;
            A[10] = a02;
            A[11] = a12;
            A[12] = a22;
            A[13] = a32;
            A[14] = a42;
            A[15] = a03;
            A[16] = a13;
            A[17] = a23;
            A[18] = a33;
            A[19] = a43;
            A[20] = a04;
            A[21] = a14;
            A[22] = a24;
            A[23] = a34;
            A[24] = a44;

        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private ulong RotateLaneByXBits(ulong lane, int offset, int laneWBits)
        {
            return lane << offset % laneWBits ^ lane >> laneWBits - offset % laneWBits;
        }


    }
}
