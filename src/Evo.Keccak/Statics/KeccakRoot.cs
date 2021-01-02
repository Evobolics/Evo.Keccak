using Evo.Services.Cryptography;

namespace Evo.Statics
{
    public class KeccakRoot
    {
        public static Keccak256Service Keccak256 { get; set; } = new Keccak256Service();
    }
}
