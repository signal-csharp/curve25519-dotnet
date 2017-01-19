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
    public class Fe_sqrt
    {
        /* sqrt(-1) */
        public static byte[] i_bytes = new byte[]
        {
            0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
            0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
            0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b,
            0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b
        };

        /* Preconditions: a is square or zero */
        public static void fe_sqrt(int[] iOut, int[] a)
        {
            int[] exp = new int[10];
            int[] b = new int[10];
            int[] b2 = new int[10];
            int[] bi = new int[10];
            int[] i = new int[10];

            Fe_frombytes.fe_frombytes(i, i_bytes);
            Fe_pow22523.fe_pow22523(exp, a);    /* b = a^(q-5)/8 */

            /* PRECONDITION: legendre symbol == 1 (square) or 0 (a == zero) */
            //#ifndef NDEBUG
            //fe legendre, zero, one;
            //fe_sq(legendre, exp);            /* in^((q-5)/4) */
            //fe_sq(legendre, legendre);       /* in^((q-5)/2) */
            //fe_mul(legendre, legendre, a);   /* in^((q-3)/2) */
            //fe_mul(legendre, legendre, a);   /* in^((q-1)/2) */

            //fe_0(zero);
            //fe_1(one);
            //assert(fe_isequal(legendre, zero) || fe_isequal(legendre, one));
            //#endif

            Fe_mul.fe_mul(b, a, exp);           /* b = a * a^(q-5)/8 */
            Fe_sq.fe_sq(b2, b);                 /* b^2 = a * a^(q-1)/4 */

            /* note b^4 == a^2, so b^2 == a or -a
             * if b^2 != a, multiply it by sqrt(-1) */
            Fe_mul.fe_mul(bi, b, i);
            Fe_cmov.fe_cmov(b, bi, 1 ^ Fe_isequal.fe_isequal(b2, a));
            Fe_copy.fe_copy(iOut, b);

            /* PRECONDITION: out^2 == a */
            //#ifndef NDEBUG
            //fe_sq(b2, out);
            //assert(fe_isequal(a, b2));
            //#endif 
        }
    }
}
