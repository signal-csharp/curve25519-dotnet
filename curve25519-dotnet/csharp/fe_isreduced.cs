using System;
using org.whispersystems.curve25519.csharp;

namespace curve25519_dotnet.csharp
{
    public class Fe_isreduced
    {
        public static bool fe_isreduced(ReadOnlySpan<byte> curve25519_pubkey)
        {
            int[] fe = new int[10];
            Span<byte> strict = new Span<byte>(new byte[32]);

            Fe_frombytes.fe_frombytes(fe, curve25519_pubkey);
            Fe_tobytes.fe_tobytes(strict, fe);
            if (Crypto_verify_32.crypto_verify_32(strict, curve25519_pubkey) != 0)
                return false;
            return true;
        }
    }
}
