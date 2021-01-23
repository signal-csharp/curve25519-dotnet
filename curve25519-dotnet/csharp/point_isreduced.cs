using System;
using curve25519_dotnet.csharp;

namespace org.whispersystems.curve25519.csharp
{
    public class Point_isreduced
    {
        public static bool point_isreduced(ReadOnlySpan<byte> p)
        {
            Span<byte> strict = new Span<byte>(new byte[32]);

            p.Slice(0, 32).CopyTo(strict);
            strict[31] &= 0x7F; /* mask off sign bit */
            return Fe_isreduced.fe_isreduced(strict);
        }
    }
}
