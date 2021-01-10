using Evo.Services.Cryptography;

namespace Evo.Statics
{
    public class KeccakRoot
    {
        public static Keccak256HashService Keccak256 { get; set; } = new Keccak256HashService();
    }
}
