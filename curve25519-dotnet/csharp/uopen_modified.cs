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

using System;

namespace org.whispersystems.curve25519.csharp
{
    public class uopen_modified
    {
        public static int crypto_usign_open_modified(ISha512 sha512provider, byte[] m, long mlen, byte[] sm, long smlen, byte[] pk, Ge_p3 Bu)
        {
            Ge_p3 U = new Ge_p3();
            byte[] h = new byte[64];
            byte[] s = new byte[64];
            byte[] strict = new byte[64];
            Ge_p3 A = new Ge_p3();
            Ge_p2 R = new Ge_p2();
            byte[] hcheck = new byte[64];
            int count;

            if (smlen < 96)
            {
                return -1;
            }
            if ((sm[63] & 224) != 0) /* strict parsing of h */
            {
                return -1;
            }
            if ((sm[95] & 224) != 0) /* strict parsing of s */
            {
                return -1;
            }

            /* Load -A */
            if (Ge_frombytes.ge_frombytes_negate_vartime(A, pk) != 0)
            {
                return -1;
            }

            /* Load -U, h, s */
            Ge_frombytes.ge_frombytes_negate_vartime(U, sm);
            Array.Copy(sm, 32, h, 0, 32);
            Array.Copy(sm, 64, s, 0, 32);

            /* Insist that s and h are reduced scalars (strict parsing) */
            Array.Copy(h, 0, strict, 0, 64);
            Sc_reduce.sc_reduce(strict);
            if (!Arrays.isEqual(strict, h, 32))
            {
                return -1;
            }
            Array.Copy(s, 0, strict, 0, 64);
            Sc_reduce.sc_reduce(strict);
            if (!Arrays.isEqual(strict, s, 32))
            {
                return -1;
            }

            /* Reject U (actually -U) if small order */
            if (Ge_is_small_order.ge_is_small_order(U) != 0)
            {
                return -1;
            }

            // R = sB + h(-A)
            Ge_double_scalarmult.ge_double_scalarmult_vartime(R, h, A, s);

            // Ru = sBu + h(-U)
            Ge_p3 sBu = new Ge_p3();
            Ge_p3 hU = new Ge_p3();

            // sBu
            Ge_scalarmult.ge_scalarmult(sBu, s, Bu);

            // h(-U)
            Ge_scalarmult.ge_scalarmult(hU, h, U);

            // Ru = sBu + h(-U)
            Ge_p1p1 Rp1p1 = new Ge_p1p1();
            Ge_p3 Ru = new Ge_p3();
            Ge_cached hUcached = new Ge_cached();
            Ge_p3_to_cached.ge_p3_to_cached(hUcached, hU);
            Ge_add.ge_add(Rp1p1, sBu, hUcached);
            Ge_p1p1_to_p3.ge_p1p1_to_p3(Ru, Rp1p1);


            // Check h == SHA512(label(4) || A || U || R || Ru || M)
            m[0] = 0xFB;
            for (count = 1; count < 32; count++)
            {
                m[count] = 0xFF;
            }
            Array.Copy(pk, 0, m, 32, 32);
            /* undo the negation for U */
            Fe_neg.fe_neg(U.X, U.X);
            Fe_neg.fe_neg(U.T, U.T);
            byte[] M = new byte[32];
            Array.Copy(m, 64, M, 0, 32);
            Ge_p3_tobytes.ge_p3_tobytes(M, U);
            Array.Copy(M, 0, m, 64, 32);
            byte[] M2 = new byte[32];
            Array.Copy(m, 96, M2, 0, 32);
            Ge_tobytes.ge_tobytes(M2, R);
            Array.Copy(M2, 0, m, 96, 32);
            byte[] M3 = new byte[32];
            Array.Copy(m, 128, M3, 0, 32);
            Ge_p3_tobytes.ge_p3_tobytes(M3, Ru);
            Array.Copy(M3, 0, m, 128, 32);
            Array.Copy(sm, 96, m, 160, (int)smlen - 96);

            sha512provider.calculateDigest(hcheck, m, smlen + 64);
            Sc_reduce.sc_reduce(hcheck);

            if (Crypto_verify_32.crypto_verify_32(hcheck, h) == 0)
            {
                Array.Copy(m, 64, m, 0, (int)smlen - 64);
                //memset(m + smlen - 64,0,64);
                //*mlen = smlen - 64;
                return 0;
            }

            //badsig:
            //*mlen = -1;
            //memset(m,0,smlen);
            return -1;
        }
    }
}
