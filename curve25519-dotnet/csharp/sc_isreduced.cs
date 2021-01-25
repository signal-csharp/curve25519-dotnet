using System;

namespace org.whispersystems.curve25519.csharp
{
    public class Sc_isreduced
    {
        public static bool sc_isreduced(byte[] s)
        {
            byte[] strict = new byte[64];

            Array.Copy(s, 0, strict, 0, 32);
            Sc_reduce.sc_reduce(strict);
            if (Crypto_verify_32.crypto_verify_32(strict, s) != 0)
                return false;
            return true;
        }
    }
}
