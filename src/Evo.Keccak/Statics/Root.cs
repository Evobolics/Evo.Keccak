using Evo.Services.Cryptography;

namespace Evo.Statics
{
    class Root
    {
        public static Keccak256Service Keccak256 { get; set; } = new Keccak256Service();
    }
}
