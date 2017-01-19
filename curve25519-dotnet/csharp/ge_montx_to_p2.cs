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
    public class Ge_montx_to_p2
    {
        /* sqrt(-(A+2)) */
        static byte[] A_bytes = new byte[]
        {
            0x06, 0x7e, 0x45, 0xff, 0xaa, 0x04, 0x6e, 0xcc,
            0x82, 0x1a, 0x7d, 0x4b, 0xd1, 0xd3, 0xa1, 0xc5,
            0x7e, 0x4f, 0xfc, 0x03, 0xdc, 0x08, 0x7b, 0xd2,
            0xbb, 0x06, 0xa0, 0x60, 0xf4, 0xed, 0x26, 0x0f
        };

        public static void ge_montx_to_p2(Ge_p2 p, int[] u, byte ed_sign_bit)
        {
            int[] x = new int[10];
            int[] y = new int[10];
            int[] A = new int[10];
            int[] v = new int[10];
            int[] v2 = new int[10];
            int[] iv = new int[10];
            int[] nx = new int[10];

            Fe_frombytes.fe_frombytes(A, A_bytes);

            /* given u, recover edwards y */
            /* given u, recover v */
            /* given u and v, recover edwards x */

            Fe_montx_to_edy.fe_montx_to_edy(y, u);      /* y = (u - 1) / (u + 1) */

            Fe_mont_rhs.fe_mont_rhs(v2, u);             /* v^2 = u(u^2 + Au + 1) */
            Fe_sqrt.fe_sqrt(v, v2);                     /* v = sqrt(v^2) */

            Fe_mul.fe_mul(x, u, A);                     /* x = u * sqrt(-(A+2)) */
            Fe_invert.fe_invert(iv, v);                 /* 1/v */
            Fe_mul.fe_mul(x, x, iv);                    /* x = (u/v) * sqrt(-(A+2)) */

            Fe_neg.fe_neg(nx, x);                       /* negate x to match sign bit */
            Fe_cmov.fe_cmov(x, nx, Fe_isnegative.fe_isnegative(x) ^ ed_sign_bit);

            Fe_copy.fe_copy(p.X, x);
            Fe_copy.fe_copy(p.Y, y);
            Fe_1.fe_1(p.Z);

            /* POSTCONDITION: check that p->X and p->Y satisfy the Ed curve equation */
            /* -x^2 + y^2 = 1 + dx^2y^2 */
            //#ifndef NDEBUG
            //{
            //fe one, d, x2, y2, x2y2, dx2y2;
            //
            //unsigned char dbytes[32] = {
            //0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
            //0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
            //0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
            //0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52
            //};
            //
            //fe_frombytes(d, dbytes);
            //fe_1(one);
            //fe_sq(x2, p->X);                /* x^2 */
            //fe_sq(y2, p->Y);                /* y^2 */
            //
            //fe_mul(dx2y2, x2, y2);           /* x^2y^2 */
            //fe_mul(dx2y2, dx2y2, d);         /* dx^2y^2 */
            //fe_add(dx2y2, dx2y2, one);       /* dx^2y^2 + 1 */
            //fe_neg(x2y2, x2);                /* -x^2 */
            //fe_add(x2y2, x2y2, y2);          /* -x^2 + y^2 */
            //
            //assert(fe_isequal(x2y2, dx2y2));
            //}
            //#endif
        }
    }
}
