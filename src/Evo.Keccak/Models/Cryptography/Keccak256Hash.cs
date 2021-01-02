using Evo.Keccak;
using Evo.Services.Cryptography;
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
        private static readonly ulong[] RoundConstants =
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
                return ComputeHashBytes(Array.Empty<byte>());
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
        private Keccak256Hash(int size)
        {
            // Set the hash size
            HashSize = size;

            // Verify the size
            if (HashSize <= 0 || HashSize > Keccak256Service.STATE_SIZE)
            {
                throw new ArgumentException($"Invalid Keccak hash size. Must be between 0 and {Keccak256Service.STATE_SIZE}.");
            }

            // The round size.
            _roundSize = Keccak256Service.STATE_SIZE == HashSize ? Keccak256Service.HASH_DATA_AREA : Keccak256Service.STATE_SIZE - 2 * HashSize;

            // The size of a round in terms of ulong.
            _roundSizeU64 = _roundSize / 8;

            // Allocate our remainder buffer
            _remainderBuffer = new byte[_roundSize];
            _remainderLength = 0;
        }
        #endregion

        #region Functions

        public static Keccak256Hash Create(int size = Keccak256Service.HASH_SIZE)
        {
            return new Keccak256Hash(size);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong ROL(ulong a, int offset)
        {
            return a << offset % Keccak256Service.LANE_BITS ^ a >> Keccak256Service.LANE_BITS - offset % Keccak256Service.LANE_BITS;
        }

        // update the state with given number of rounds
        public static void KeccakF(Span<ulong> st, int rounds)
        {
            Debug.Assert(st.Length == 25);

            ulong aba, abe, abi, abo, abu;
            ulong aga, age, agi, ago, agu;
            ulong aka, ake, aki, ako, aku;
            ulong ama, ame, ami, amo, amu;
            ulong asa, ase, asi, aso, asu;
            ulong bCa, bCe, bCi, bCo, bCu;
            ulong da, de, di, @do, du;
            ulong eba, ebe, ebi, ebo, ebu;
            ulong ega, ege, egi, ego, egu;
            ulong eka, eke, eki, eko, eku;
            ulong ema, eme, emi, emo, emu;
            ulong esa, ese, esi, eso, esu;

            //copyFromState(A, state)
            aba = st[0];
            abe = st[1];
            abi = st[2];
            abo = st[3];
            abu = st[4];
            aga = st[5];
            age = st[6];
            agi = st[7];
            ago = st[8];
            agu = st[9];
            aka = st[10];
            ake = st[11];
            aki = st[12];
            ako = st[13];
            aku = st[14];
            ama = st[15];
            ame = st[16];
            ami = st[17];
            amo = st[18];
            amu = st[19];
            asa = st[20];
            ase = st[21];
            asi = st[22];
            aso = st[23];
            asu = st[24];

            for (var round = 0; round < Keccak256Service.ROUNDS; round += 2)
            {
                //    prepareTheta
                bCa = aba ^ aga ^ aka ^ ama ^ asa;
                bCe = abe ^ age ^ ake ^ ame ^ ase;
                bCi = abi ^ agi ^ aki ^ ami ^ asi;
                bCo = abo ^ ago ^ ako ^ amo ^ aso;
                bCu = abu ^ agu ^ aku ^ amu ^ asu;

                //thetaRhoPiChiIotaPrepareTheta(round  , A, E)
                da = bCu ^ ROL(bCe, 1);
                de = bCa ^ ROL(bCi, 1);
                di = bCe ^ ROL(bCo, 1);
                @do = bCi ^ ROL(bCu, 1);
                du = bCo ^ ROL(bCa, 1);

                aba ^= da;
                bCa = aba;
                age ^= de;
                bCe = ROL(age, 44);
                aki ^= di;
                bCi = ROL(aki, 43);
                amo ^= @do;
                bCo = ROL(amo, 21);
                asu ^= du;
                bCu = ROL(asu, 14);
                eba = bCa ^ ~bCe & bCi;
                eba ^= RoundConstants[round];
                ebe = bCe ^ ~bCi & bCo;
                ebi = bCi ^ ~bCo & bCu;
                ebo = bCo ^ ~bCu & bCa;
                ebu = bCu ^ ~bCa & bCe;

                abo ^= @do;
                bCa = ROL(abo, 28);
                agu ^= du;
                bCe = ROL(agu, 20);
                aka ^= da;
                bCi = ROL(aka, 3);
                ame ^= de;
                bCo = ROL(ame, 45);
                asi ^= di;
                bCu = ROL(asi, 61);
                ega = bCa ^ ~bCe & bCi;
                ege = bCe ^ ~bCi & bCo;
                egi = bCi ^ ~bCo & bCu;
                ego = bCo ^ ~bCu & bCa;
                egu = bCu ^ ~bCa & bCe;

                abe ^= de;
                bCa = ROL(abe, 1);
                agi ^= di;
                bCe = ROL(agi, 6);
                ako ^= @do;
                bCi = ROL(ako, 25);
                amu ^= du;
                bCo = ROL(amu, 8);
                asa ^= da;
                bCu = ROL(asa, 18);
                eka = bCa ^ ~bCe & bCi;
                eke = bCe ^ ~bCi & bCo;
                eki = bCi ^ ~bCo & bCu;
                eko = bCo ^ ~bCu & bCa;
                eku = bCu ^ ~bCa & bCe;

                abu ^= du;
                bCa = ROL(abu, 27);
                aga ^= da;
                bCe = ROL(aga, 36);
                ake ^= de;
                bCi = ROL(ake, 10);
                ami ^= di;
                bCo = ROL(ami, 15);
                aso ^= @do;
                bCu = ROL(aso, 56);
                ema = bCa ^ ~bCe & bCi;
                eme = bCe ^ ~bCi & bCo;
                emi = bCi ^ ~bCo & bCu;
                emo = bCo ^ ~bCu & bCa;
                emu = bCu ^ ~bCa & bCe;

                abi ^= di;
                bCa = ROL(abi, 62);
                ago ^= @do;
                bCe = ROL(ago, 55);
                aku ^= du;
                bCi = ROL(aku, 39);
                ama ^= da;
                bCo = ROL(ama, 41);
                ase ^= de;
                bCu = ROL(ase, 2);
                esa = bCa ^ ~bCe & bCi;
                ese = bCe ^ ~bCi & bCo;
                esi = bCi ^ ~bCo & bCu;
                eso = bCo ^ ~bCu & bCa;
                esu = bCu ^ ~bCa & bCe;

                //    prepareTheta
                bCa = eba ^ ega ^ eka ^ ema ^ esa;
                bCe = ebe ^ ege ^ eke ^ eme ^ ese;
                bCi = ebi ^ egi ^ eki ^ emi ^ esi;
                bCo = ebo ^ ego ^ eko ^ emo ^ eso;
                bCu = ebu ^ egu ^ eku ^ emu ^ esu;

                //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
                da = bCu ^ ROL(bCe, 1);
                de = bCa ^ ROL(bCi, 1);
                di = bCe ^ ROL(bCo, 1);
                @do = bCi ^ ROL(bCu, 1);
                du = bCo ^ ROL(bCa, 1);

                eba ^= da;
                bCa = eba;
                ege ^= de;
                bCe = ROL(ege, 44);
                eki ^= di;
                bCi = ROL(eki, 43);
                emo ^= @do;
                bCo = ROL(emo, 21);
                esu ^= du;
                bCu = ROL(esu, 14);
                aba = bCa ^ ~bCe & bCi;
                aba ^= RoundConstants[round + 1];
                abe = bCe ^ ~bCi & bCo;
                abi = bCi ^ ~bCo & bCu;
                abo = bCo ^ ~bCu & bCa;
                abu = bCu ^ ~bCa & bCe;

                ebo ^= @do;
                bCa = ROL(ebo, 28);
                egu ^= du;
                bCe = ROL(egu, 20);
                eka ^= da;
                bCi = ROL(eka, 3);
                eme ^= de;
                bCo = ROL(eme, 45);
                esi ^= di;
                bCu = ROL(esi, 61);
                aga = bCa ^ ~bCe & bCi;
                age = bCe ^ ~bCi & bCo;
                agi = bCi ^ ~bCo & bCu;
                ago = bCo ^ ~bCu & bCa;
                agu = bCu ^ ~bCa & bCe;

                ebe ^= de;
                bCa = ROL(ebe, 1);
                egi ^= di;
                bCe = ROL(egi, 6);
                eko ^= @do;
                bCi = ROL(eko, 25);
                emu ^= du;
                bCo = ROL(emu, 8);
                esa ^= da;
                bCu = ROL(esa, 18);
                aka = bCa ^ ~bCe & bCi;
                ake = bCe ^ ~bCi & bCo;
                aki = bCi ^ ~bCo & bCu;
                ako = bCo ^ ~bCu & bCa;
                aku = bCu ^ ~bCa & bCe;

                ebu ^= du;
                bCa = ROL(ebu, 27);
                ega ^= da;
                bCe = ROL(ega, 36);
                eke ^= de;
                bCi = ROL(eke, 10);
                emi ^= di;
                bCo = ROL(emi, 15);
                eso ^= @do;
                bCu = ROL(eso, 56);
                ama = bCa ^ ~bCe & bCi;
                ame = bCe ^ ~bCi & bCo;
                ami = bCi ^ ~bCo & bCu;
                amo = bCo ^ ~bCu & bCa;
                amu = bCu ^ ~bCa & bCe;

                ebi ^= di;
                bCa = ROL(ebi, 62);
                ego ^= @do;
                bCe = ROL(ego, 55);
                eku ^= du;
                bCi = ROL(eku, 39);
                ema ^= da;
                bCo = ROL(ema, 41);
                ese ^= de;
                bCu = ROL(ese, 2);
                asa = bCa ^ ~bCe & bCi;
                ase = bCe ^ ~bCi & bCo;
                asi = bCi ^ ~bCo & bCu;
                aso = bCo ^ ~bCu & bCa;
                asu = bCu ^ ~bCa & bCe;
            }

            //copyToState(state, A)
            st[0] = aba;
            st[1] = abe;
            st[2] = abi;
            st[3] = abo;
            st[4] = abu;
            st[5] = aga;
            st[6] = age;
            st[7] = agi;
            st[8] = ago;
            st[9] = agu;
            st[10] = aka;
            st[11] = ake;
            st[12] = aki;
            st[13] = ako;
            st[14] = aku;
            st[15] = ama;
            st[16] = ame;
            st[17] = ami;
            st[18] = amo;
            st[19] = amu;
            st[20] = asa;
            st[21] = ase;
            st[22] = asi;
            st[23] = aso;
            st[24] = asu;
        }

        /// <summary>
        /// Computes the hash of a string using UTF8 encoding.
        /// </summary>
        /// <param name="utf8String">String to be converted to UTF8 bytes and hashed.</param>
        /// <returns></returns>
        public static byte[] FromString(string utf8String)
        {
            var input = StringUtil.UTF8.GetBytes(utf8String);
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
        public static byte[] FromString(string inputString, Encoding stringEncoding)
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
        public static byte[] FromHex(string hexString)
        {
            var input = HexUtil.HexToBytes(hexString);
            var output = new byte[32];
            ComputeHash(input, output);
            return output;
        }

        public static Span<byte> ComputeHash(Span<byte> input, int size = Keccak256Service.HASH_SIZE)
        {
            Span<byte> output = new byte[size];
            ComputeHash(input, output);
            return output;
        }

        public static byte[] ComputeHashBytes(Span<byte> input, int size = Keccak256Service.HASH_SIZE)
        {
            var output = new byte[Keccak256Service.HASH_SIZE];
            ComputeHash(input, output);
            return output;
        }

        static readonly ArrayPool<byte> _arrayPool = ArrayPool<byte>.Shared;


        // compute a keccak hash (md) of given byte length from "in"
        public static void ComputeHash(Span<byte> input, Span<byte> output)
        {
            if (output.Length <= 0 || output.Length > Keccak256Service.STATE_SIZE)
            {
                throw new ArgumentException("Bad keccak use");
            }

            byte[] stateArray = _arrayPool.Rent(Keccak256Service.STATE_SIZE);
            byte[] tempArray = _arrayPool.Rent(Keccak256Service.TEMP_BUFF_SIZE);

            try
            {
                Span<ulong> state = MemoryMarshal.Cast<byte, ulong>(stateArray.AsSpan(0, Keccak256Service.STATE_SIZE));
                Span<byte> temp = tempArray.AsSpan(0, Keccak256Service.TEMP_BUFF_SIZE);

                state.Clear();
                temp.Clear();

                int roundSize = Keccak256Service.STATE_SIZE == output.Length ? Keccak256Service.HASH_DATA_AREA : Keccak256Service.STATE_SIZE - 2 * output.Length;
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

                    KeccakF(state, Keccak256Service.ROUNDS);
                }

                // last block and padding
                if (inputLength >= Keccak256Service.TEMP_BUFF_SIZE || inputLength > roundSize || roundSize - inputLength + inputLength + 1 >= Keccak256Service.TEMP_BUFF_SIZE || roundSize == 0 || roundSize - 1 >= Keccak256Service.TEMP_BUFF_SIZE || roundSizeU64 * 8 > Keccak256Service.TEMP_BUFF_SIZE)
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

                KeccakF(state, Keccak256Service.ROUNDS);
                MemoryMarshal.AsBytes(state).Slice(0, output.Length).CopyTo(output);
            }
            finally
            {
                _arrayPool.Return(stateArray);
                _arrayPool.Return(tempArray);
            }
        }

        public static void Keccak1600(Span<byte> input, Span<byte> output)
        {
            if (output.Length != Keccak256Service.STATE_SIZE)
            {
                throw new ArgumentException($"Output length must be {Keccak256Service.STATE_SIZE} bytes");
            }

            ComputeHash(input, output);
        }

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
                _state = new ulong[Keccak256Service.STATE_SIZE / 8];
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
                    KeccakF(_state.Span, Keccak256Service.ROUNDS);

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
                KeccakF(_state.Span, Keccak256Service.ROUNDS);

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

            KeccakF(_state.Span, Keccak256Service.ROUNDS);

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
