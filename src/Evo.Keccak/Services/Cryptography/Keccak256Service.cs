﻿using Evo.Keccak;
using Evo.Models.Cryptography;
using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace Evo.Services.Cryptography
{
    public class Keccak256Service : Keccak256Service_I
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

        public Keccak256Hash Create(int size = Keccak256Service.HASH_SIZE_InBytes)
        {
            return new Keccak256Hash(size);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private ulong ROL(ulong a, int offset)
        {
            return a << offset % Keccak256Service.LANE_BITS ^ a >> Keccak256Service.LANE_BITS - offset % Keccak256Service.LANE_BITS;
        }

        // update the state with given number of rounds
        public void KeccakF(Span<ulong> st, int rounds)
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
                eba ^= Keccak256Service.RoundConstants[round];
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
                aba ^= Keccak256Service.RoundConstants[round + 1];
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
        public byte[] FromString(string utf8String)
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

        public Span<byte> ComputeHash(Span<byte> input, int size = Keccak256Service.HASH_SIZE_InBytes)
        {
            Span<byte> output = new byte[size];
            ComputeHash(input, output);
            return output;
        }

        public byte[] ComputeHashBytes(Span<byte> input, int size = Keccak256Service.HASH_SIZE_InBytes)
        {
            var output = new byte[Keccak256Service.HASH_SIZE_InBytes];
            ComputeHash(input, output);
            return output;
        }

        


        // compute a keccak hash (md) of given byte length from "in"
        public void ComputeHash(Span<byte> input, Span<byte> output)
        {
            if (output.Length <= 0 || output.Length > Keccak256Service.State_Size_B_InBytes)
            {
                throw new ArgumentException("Bad keccak use");
            }

            byte[] stateArray = _arrayPool.Rent(Keccak256Service.State_Size_B_InBytes);
            byte[] tempArray = _arrayPool.Rent(Keccak256Service.TEMP_BUFF_SIZE);

            try
            {
                Span<ulong> state = MemoryMarshal.Cast<byte, ulong>(stateArray.AsSpan(0, Keccak256Service.State_Size_B_InBytes));
                Span<byte> temp = tempArray.AsSpan(0, Keccak256Service.TEMP_BUFF_SIZE);

                state.Clear();
                temp.Clear();

                int roundSize = Keccak256Service.State_Size_B_InBytes == output.Length ? Keccak256Service.HASH_DATA_AREA : Keccak256Service.State_Size_B_InBytes - 2 * output.Length;
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

        public void Keccak1600(Span<byte> input, Span<byte> output)
        {
            if (output.Length != Keccak256Service.State_Size_B_InBytes)
            {
                throw new ArgumentException($"Output length must be {Keccak256Service.State_Size_B_InBytes} bytes");
            }

            ComputeHash(input, output);
        }
    }
}
