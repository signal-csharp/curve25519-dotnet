/** 
 * Copyright (C) 2017 golf1052
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
    public class Elligator
    {
        public static int legendre_is_nonsquare(int[] iIn)
        {
            int[] temp = new int[10];
            byte[] bytes = new byte[32];
            Fe_pow22523.fe_pow22523(temp, iIn); /* temp = in^((q-5)/8) */
            Fe_sq.fe_sq(temp, temp);            /*        in^((q-5)/4) */
            Fe_sq.fe_sq(temp, temp);            /*        in^((q-5)/2) */
            Fe_mul.fe_mul(temp, temp, iIn);     /*        in^((q-3)/2) */
            Fe_mul.fe_mul(temp, temp, iIn);     /*        in^((q-1)/2) */


            /* temp is now the Legendre symbol:
             * 1 = square
             * 0 = input is zero
             * -1 = nonsquare
             */
            Fe_tobytes.fe_tobytes(bytes, temp);
            return 1 & bytes[31];
        }

        public static void elligator(int[] u, int[] r)
        {
            /* r = input
             * x = -A/(1+2r^2)                  # 2 is nonsquare
             * e = (x^3 + Ax^2 + x)^((q-1)/2)   # legendre symbol
             * if e == 1 (square) or e == 0 (because x == 0 and 2r^2 + 1 == 0)
             *   u = x
             * if e == -1 (nonsquare)
             *   u = -x - A
             */

            int[] A = new int[10];
            int[] one = new int[10];
            int[] twor2 = new int[10];
            int[] twor2plus1 = new int[10];
            int[] twor2plus1inv = new int[10];

            int[] x = new int[10];
            int[] e = new int[10];
            int[] Atemp = new int[10];
            int[] uneg = new int[10];
            int nonsquare;

            Fe_1.fe_1(one);
            Fe_0.fe_0(A);
            A[0] = 486662;                                      /* A = 486662 */

            Fe_sq2.fe_sq2(twor2, r);                            /* 2r^2 */
            Fe_add.fe_add(twor2plus1, twor2, one);              /* 1+2r^2 */
            Fe_invert.fe_invert(twor2plus1inv, twor2plus1);     /* 1/(1+2r^2) */
            Fe_mul.fe_mul(x, twor2plus1inv, A);                 /* A/(1+2r^2) */
            Fe_neg.fe_neg(x, x);                                /* x = -A/(1+2r^2) */

            Fe_mont_rhs.fe_mont_rhs(e, x);                      /* e = x^3 + Ax^2 + x */
            nonsquare = legendre_is_nonsquare(e);

            Fe_0.fe_0(Atemp);
            Fe_cmov.fe_cmov(Atemp, A, nonsquare);               /* 0, or A if nonsquare */
            Fe_add.fe_add(u, x, Atemp);                         /* x, or x+A if nonsquare */
            Fe_neg.fe_neg(uneg, u);                             /* -x, or -x-A if nonsquare */
            Fe_cmov.fe_cmov(u, uneg, nonsquare);                /* x, or -x-A if nonsquare */
        }

        public static void hash_to_point(ISha512 sha512provider, Ge_p3 p, ReadOnlySpan<byte> iIn, int in_len)
        {
            byte[] hashArr = new byte[64];
            Span<byte> hash = new Span<byte>(hashArr);
            int[] h = new int[10];
            int[] u = new int[10];
            byte sign_bit;
            Ge_p3 p3 = new Ge_p3();

            sha512provider.calculateDigest(hashArr, iIn.ToArray(), in_len);

            /* take the high bit as Edwards sign bit */
            sign_bit = (byte)(((uint)hash[31] & 0x80) >> 7);
            hash[31] &= 0x7F;
            Fe_frombytes.fe_frombytes(h, hash);
            elligator(u, h);

            Ge_montx_to_p3.ge_montx_to_p3(p3, u, sign_bit);
            Ge_scalarmult_cofactor.ge_scalarmult_cofactor(p, p3);
        }

        public static void calculate_Bv(ISha512 sha512provider,
            Ge_p3 Bv,
            byte[] buf,
            byte[] A,
            byte[] msg, int msg_len)
        {
            int count;

            /* Calculate SHA512(label(2) || A || msg) */
            buf[0] = 0xFD;
            for (count = 1; count < 32; count++)
            {
                buf[count] = 0xFF;
            }
            Array.Copy(A, 0, buf, 32, 32);
            Array.Copy(msg, 0, buf, 64, msg_len);

            hash_to_point(sha512provider, Bv, buf, 64 + msg_len);
        }

        public static void calculate_Bv_and_V(ISha512 sha512provider,
            Ge_p3 Bv,
            byte[] V,
            byte[] buf,
            byte[] a,
            byte[] A,
            byte[] msg, int msg_len)
        {
            Ge_p3 p3 = new Ge_p3();

            calculate_Bv(sha512provider, Bv, buf, A, msg, msg_len);
            Ge_scalarmult.ge_scalarmult(p3, a, Bv);
            Ge_p3_tobytes.ge_p3_tobytes(V, p3);
        }
    }
}
