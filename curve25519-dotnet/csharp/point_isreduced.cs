using System;
using curve25519_dotnet.csharp;

namespace org.whispersystems.curve25519.csharp
{
    public class Point_isreduced
    {
        public static bool point_isreduced(byte[] p)
        {
            byte[] strict = new byte[32];

            Array.Copy(p, 0, strict, 0, 32);
            strict[31] &= 0x7F; /* mask off sign bit */
            return Fe_isreduced.fe_isreduced(strict);
        }
    }
}
