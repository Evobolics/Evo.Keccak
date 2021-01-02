namespace Evo.Services.Cryptography
{
    public class Keccak256Service : Keccak256Service_I
    {
        #region Constants
        public const int HASH_SIZE = 32;
        public const int STATE_SIZE = 200;
        public const int HASH_DATA_AREA = 136;
        public const int ROUNDS = 24;
        public const int LANE_BITS = 8 * 8;
        public const int TEMP_BUFF_SIZE = 144;
        #endregion
    }
}
