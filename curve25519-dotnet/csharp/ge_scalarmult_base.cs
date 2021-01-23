/** 
 * Copyright (C) 2015 langboost
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;

namespace org.whispersystems.curve25519.csharp
{

    public class Ge_scalarmult_base
    {

        //CONVERT #include "ge.h"
        //CONVERT #include "crypto_uint32.h"
        /// <summary>
        /// Constant-time equals comparison (resists side-channel attacks by avoiding branching)
        /// </summary>
        /// <returns>1 for yes, 0 for no</returns>

        public static int equal(byte b, byte c)
        {
            //uint ub = b;
            //uint uc = c;
            //uint x = ub ^ uc; /* 0: yes; 1..255: no */
            //uint y = x; /* 0: yes; 1..255: no */
            //y -= 1; /* 4294967295: yes; 0..254: no */
            //uint result = y >> 31; /* 1: yes; 0: no */
            //return (int)result;

            uint result = (uint)(b ^ c);//0: yes, 1..255 no (bytes are always 8 bits in .NET, so the highest "difference" number would be 255)
            result--; //subtract by 1. If it was 0:, we now have a large in32 (0xFFFF FFFF) number
            //right shift zero fill by 31 to leave just the left-most bit... 1 = yes, 0 = no for "equals"
            uint uresult = result >> 31;
            return (int)uresult;
        }

        public static int negative(sbyte b)
        {
            long x = b;//Value will be expanded and given a sign bit, according to the signed byte (0x0000....0b vs 0xFFFF....b1
            ulong ux = (ulong)x; //make it unsigned for zero-filled bit shifting
            ux = ux >> 63; /* Shift to just the sign bit - 1: yes; 0: no */
            return (int)ux;
        }

        static void cmov(Ge_precomp t, Ge_precomp u, int b)
        {
            Fe_cmov.fe_cmov(t.yplusx, u.yplusx, b);
            Fe_cmov.fe_cmov(t.yminusx, u.yminusx, b);
            Fe_cmov.fe_cmov(t.xy2d, u.xy2d, b);
        }

        static void select(Ge_precomp t, int pos, byte b)
        {
            Ge_precomp[,] gepc_base = (pos <= 7 ? Ge_precomp_base_0_7.gepc_base :
                                     (pos <= 15 ? Ge_precomp_base_8_15.gepc_base :
                                       (pos <= 23 ? Ge_precomp_base_16_23.gepc_base : Ge_precomp_base_24_31.gepc_base)));

            Ge_precomp minust = new Ge_precomp();
            int bnegative = negative((sbyte)b);
            int babs = b - (((-bnegative) & b) << 1);

            Ge_precomp_0.ge_precomp_0(t);
            cmov(t, gepc_base[pos, 0], equal((byte)babs, (byte)1));
            cmov(t, gepc_base[pos, 1], equal((byte)babs, (byte)2));
            cmov(t, gepc_base[pos, 2], equal((byte)babs, (byte)3));
            cmov(t, gepc_base[pos, 3], equal((byte)babs, (byte)4));
            cmov(t, gepc_base[pos, 4], equal((byte)babs, (byte)5));
            cmov(t, gepc_base[pos, 5], equal((byte)babs, (byte)6));
            cmov(t, gepc_base[pos, 6], equal((byte)babs, (byte)7));
            cmov(t, gepc_base[pos, 7], equal((byte)babs, (byte)8));
            Fe_copy.fe_copy(minust.yplusx, t.yminusx);
            Fe_copy.fe_copy(minust.yminusx, t.yplusx);
            Fe_neg.fe_neg(minust.xy2d, t.xy2d);
            cmov(t, minust, bnegative);
        }

        /*
        h = a * B
        where a = a[0]+256*a[1]+...+256^31 a[31]
        B is the Ed25519 base point (x,4/5) with x positive.

        Preconditions:
          a[31] <= 127
        */

        public static void ge_scalarmult_base(Ge_p3 h, ReadOnlySpan<byte> a)
        {
            byte[] e = new byte[64];
            byte carry;
            Ge_p1p1 r = new Ge_p1p1();
            Ge_p2 s = new Ge_p2();
            Ge_precomp t = new Ge_precomp();
            int i;

            for (i = 0; i < 32; ++i)
            {
                e[2 * i + 0] = (byte)((((uint)a[i]) >> 0) & 15);
                e[2 * i + 1] = (byte)((((uint)a[i]) >> 4) & 15);
            }
            /* each e[i] is between 0 and 15 */
            /* e[63] is between 0 and 7 */

            carry = 0;
            for (i = 0; i < 63; ++i)
            {
                e[i] += carry;
                carry = (byte)(e[i] + 8);
                carry >>= 4;
                e[i] -= (byte)(carry << 4);
            }
            e[63] += carry;
            /* each e[i] is between -8 and 8 */

            Ge_p3_0.ge_p3_0(h);
            for (i = 1; i < 64; i += 2)
            {
                select(t, i / 2, e[i]);
                Ge_madd.ge_madd(r, h, t); Ge_p1p1_to_p3.ge_p1p1_to_p3(h, r);
            }

            Ge_p3_dbl.ge_p3_dbl(r, h); Ge_p1p1_to_p2.ge_p1p1_to_p2(s, r);
            Ge_p2_dbl.ge_p2_dbl(r, s); Ge_p1p1_to_p2.ge_p1p1_to_p2(s, r);
            Ge_p2_dbl.ge_p2_dbl(r, s); Ge_p1p1_to_p2.ge_p1p1_to_p2(s, r);
            Ge_p2_dbl.ge_p2_dbl(r, s); Ge_p1p1_to_p3.ge_p1p1_to_p3(h, r);

            for (i = 0; i < 64; i += 2)
            {
                select(t, i / 2, e[i]);
                Ge_madd.ge_madd(r, h, t); Ge_p1p1_to_p3.ge_p1p1_to_p3(h, r);
            }
        }
    }
}
