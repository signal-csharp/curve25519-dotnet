/** 
 * Copyright (C) 2016 golf1052
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

namespace org.whispersystems.curve25519.csharp
{
    public class Ge_scalarmult
    {
        /// <summary>
        /// This is the same as Ge_scalarmult_base.equal(byte, byte)
        /// </summary>
        /// <param name="b"></param>
        /// <param name="c"></param>
        /// <returns></returns>
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

        /// <summary>
        /// This is the same as Ge_scalarmult_base.negative(sbyte)
        /// </summary>
        /// <param name="b"></param>
        /// <returns></returns>
        public static int negative(sbyte b)
        {
            long x = b;//Value will be expanded and given a sign bit, according to the signed byte (0x0000....0b vs 0xFFFF....b1
            ulong ux = (ulong)x; //make it unsigned for zero-filled bit shifting
            ux = ux >> 63; /* Shift to just the sign bit - 1: yes; 0: no */
            return (int)ux;
        }

        public static void cmov(Ge_cached t, Ge_cached u, int b)
        {
            Fe_cmov.fe_cmov(t.YplusX, u.YplusX, b);
            Fe_cmov.fe_cmov(t.YminusX, u.YminusX, b);
            Fe_cmov.fe_cmov(t.Z, u.Z, b);
            Fe_cmov.fe_cmov(t.T2d, u.T2d, b);
        }

        public static void select(Ge_cached t, Ge_cached[] pre, byte b)
        {
            Ge_cached minust = new Ge_cached();
            int bnegative = negative((sbyte)b);
            int babs = b - (((-bnegative) & b) << 1);

            Fe_1.fe_1(t.YplusX);
            Fe_1.fe_1(t.YminusX);
            Fe_1.fe_1(t.Z);
            Fe_1.fe_1(t.Z);
            Fe_0.fe_0(t.T2d);

            cmov(t, pre[0], equal((byte)babs, 1));
            cmov(t, pre[1], equal((byte)babs, 2));
            cmov(t, pre[2], equal((byte)babs, 3));
            cmov(t, pre[3], equal((byte)babs, 4));
            cmov(t, pre[4], equal((byte)babs, 5));
            cmov(t, pre[5], equal((byte)babs, 6));
            cmov(t, pre[6], equal((byte)babs, 7));
            cmov(t, pre[7], equal((byte)babs, 8));
            Fe_copy.fe_copy(minust.YplusX, t.YminusX);
            Fe_copy.fe_copy(minust.YminusX, t.YplusX);
            Fe_copy.fe_copy(minust.Z, t.Z);
            Fe_neg.fe_neg(minust.T2d, t.T2d);
            cmov(t, minust, bnegative);
        }

        /*
         * h = a * B
         * where a = a[0]+256*a[1]+...+256^31 a[31]
         * B is the Ed25519 base point (x,4/5) with x positive.
         * 
         * Preconditions:
         *   a[31] <= 127
         */

        public static void ge_scalarmult(Ge_p3 h, byte[] a, Ge_p3 A)
        {
            byte[] e = new byte[64];
            byte carry;

            Ge_p1p1 r = new Ge_p1p1();
            Ge_p2 s = new Ge_p2();
            Ge_p3 t0 = new Ge_p3();
            Ge_p3 t1 = new Ge_p3();
            Ge_p3 t2 = new Ge_p3();

            Ge_cached t = new Ge_cached();
            Ge_cached[] pre = new Ge_cached[8];
            for (int count = 0; count < pre.Length; count++)
            {
                pre[count] = new Ge_cached();
            }
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

            // Precomputation:
            Ge_p3_to_cached.ge_p3_to_cached(pre[0], A); // A

            Ge_p3_dbl.ge_p3_dbl(r, A);
            Ge_p1p1_to_p3.ge_p1p1_to_p3(t0, r);
            Ge_p3_to_cached.ge_p3_to_cached(pre[1], t0); // 2A

            Ge_add.ge_add(r, A, pre[1]);
            Ge_p1p1_to_p3.ge_p1p1_to_p3(t1, r);
            Ge_p3_to_cached.ge_p3_to_cached(pre[2], t1); // 3A

            Ge_p3_dbl.ge_p3_dbl(r, t0);
            Ge_p1p1_to_p3.ge_p1p1_to_p3(t0, r);
            Ge_p3_to_cached.ge_p3_to_cached(pre[3], t0); // 4A

            Ge_add.ge_add(r, A, pre[3]);
            Ge_p1p1_to_p3.ge_p1p1_to_p3(t2, r);
            Ge_p3_to_cached.ge_p3_to_cached(pre[4], t2); // 5A

            Ge_p3_dbl.ge_p3_dbl(r, t1);
            Ge_p1p1_to_p3.ge_p1p1_to_p3(t1, r);
            Ge_p3_to_cached.ge_p3_to_cached(pre[5], t1); // 6A

            Ge_add.ge_add(r, A, pre[5]);
            Ge_p1p1_to_p3.ge_p1p1_to_p3(t1, r);
            Ge_p3_to_cached.ge_p3_to_cached(pre[6], t1); // 7A

            Ge_p3_dbl.ge_p3_dbl(r, t0);
            Ge_p1p1_to_p3.ge_p1p1_to_p3(t0, r);
            Ge_p3_to_cached.ge_p3_to_cached(pre[7], t0); // 8A

            Ge_p3_0.ge_p3_0(h);

            for (i = 63; i > 0; i--)
            {
                select(t, pre, e[i]);
                Ge_add.ge_add(r, h, t);
                Ge_p1p1_to_p2.ge_p1p1_to_p2(s, r);

                Ge_p2_dbl.ge_p2_dbl(r, s); Ge_p1p1_to_p2.ge_p1p1_to_p2(s, r);
                Ge_p2_dbl.ge_p2_dbl(r, s); Ge_p1p1_to_p2.ge_p1p1_to_p2(s, r);
                Ge_p2_dbl.ge_p2_dbl(r, s); Ge_p1p1_to_p2.ge_p1p1_to_p2(s, r);
                Ge_p2_dbl.ge_p2_dbl(r, s); Ge_p1p1_to_p3.ge_p1p1_to_p3(h, r);
            }

            select(t, pre, e[0]);
            Ge_add.ge_add(r, h, t);
            Ge_p1p1_to_p3.ge_p1p1_to_p3(h, r);
        }
    }
}
