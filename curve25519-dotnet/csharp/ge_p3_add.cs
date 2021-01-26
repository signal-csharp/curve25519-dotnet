using System;
using System.Collections.Generic;
using System.Text;

namespace org.whispersystems.curve25519.csharp
{
    public class Ge_p3_add
    {
        /*
        r = p + q
        */
        public static void ge_p3_add(Ge_p3 r, Ge_p3 p, Ge_p3 q)
        {
            Ge_cached p_cached = new Ge_cached();
            Ge_p1p1 r_p1p1 = new Ge_p1p1();

            Ge_p3_to_cached.ge_p3_to_cached(p_cached, p);
            Ge_add.ge_add(r_p1p1, q, p_cached);
            Ge_p1p1_to_p3.ge_p1p1_to_p3(r, r_p1p1);
        }
    }
}
