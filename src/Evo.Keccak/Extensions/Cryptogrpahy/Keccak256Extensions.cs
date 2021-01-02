using Evo.Statics;

namespace Evo.Models.Cryptography
{
    public static class Keccak256Extensions
    {
        public static void Update(this Keccak256Hash keccak, byte[] array, int index, int size)
        {
            KeccakRoot.Keccak256.Update(keccak, array, index, size);
        }

        public static byte[] UpdateFinal(this Keccak256Hash keccak)
        {
            return KeccakRoot.Keccak256.UpdateFinal(keccak);
        }

        public static void Reset(this Keccak256Hash keccak)
        {
            KeccakRoot.Keccak256.Reset(keccak);
        }
    }
}
