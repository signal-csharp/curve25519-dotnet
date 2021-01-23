using System;

namespace org.whispersystems.curve25519.csharp
{
    public class Sc_isreduced
    {
        public static bool sc_isreduced(ReadOnlySpan<byte> s)
        {
            Span<byte> strict = new Span<byte>(new byte[64]);

            s.Slice(0, 32).CopyTo(strict);
            Sc_reduce.sc_reduce(strict);
            if (Crypto_verify_32.crypto_verify_32(strict, s) != 0)
                return false;
            return true;
        }
    }
}
