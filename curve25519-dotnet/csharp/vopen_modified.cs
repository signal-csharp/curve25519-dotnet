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
    public class Vopen_modified
    {
        public static int crypto_vsign_open_modified(ISha512 sha512provider,
            byte[] m,
            byte[] sm, long smlen,
            byte[] pk, Ge_p3 Bv)
        {
            Ge_p3 Vneg = new Ge_p3();
            Ge_p3 V = new Ge_p3();
            Ge_p3 Aneg = new Ge_p3();
            Ge_p3 A = new Ge_p3();
            Ge_p3 c_V = new Ge_p3();
            Ge_p3 c_A = new Ge_p3();
            Ge_p3 h_Vneg = new Ge_p3();
            Ge_p3 s_Bv = new Ge_p3();
            byte[] h = new byte[32];
            byte[] s = new byte[32];
            Ge_p2 R = new Ge_p2();
            byte[] hcheck = new byte[64];
            byte[] vrf_output = new byte[64];
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
            if (Ge_frombytes.ge_frombytes_negate_vartime(Aneg, pk) != 0)
            {
                return -1;
            }

            /* Load -V, h, s */
            if (Ge_frombytes.ge_frombytes_negate_vartime(Vneg, sm) != 0)
            {
                return -1;
            }
            Array.Copy(sm, 32, h, 0, 32);
            Array.Copy(sm, 64, s, 0, 32);
            if ((h[31] & 224) != 0) /* strict parsing of h */
            {
                return -1;
            }
            if ((s[31] & 224) != 0) /* strict parsing of s */
            {
                return -1;
            }

            Ge_neg.ge_neg(A, Aneg);
            Ge_neg.ge_neg(V, Vneg);
            Ge_scalarmult_cofactor.ge_scalarmult_cofactor(c_A, A);
            Ge_scalarmult_cofactor.ge_scalarmult_cofactor(c_V, V);
            if (Ge_isneutral.ge_isneutral(c_A) != 0 ||
                Ge_isneutral.ge_isneutral(c_V) != 0 ||
                Ge_isneutral.ge_isneutral(Bv) != 0)
            {
                return -1;
            }

            // R = (s*B) + (h * -A))
            Ge_double_scalarmult.ge_double_scalarmult_vartime(R, h, Aneg, s);

            // s * Bv
            Ge_scalarmult.ge_scalarmult(s_Bv, s, Bv);

            // h * -V
            Ge_scalarmult.ge_scalarmult(h_Vneg, h, Vneg);

            // Rv = (sc * Bv) + (hc * (-V))
            Ge_p1p1 Rp1p1 = new Ge_p1p1();
            Ge_p3 Rv = new Ge_p3();
            Ge_cached h_Vnegcached = new Ge_cached();
            Ge_p3_to_cached.ge_p3_to_cached(h_Vnegcached, h_Vneg);
            Ge_add.ge_add(Rp1p1, s_Bv, h_Vnegcached);
            Ge_p1p1_to_p3.ge_p1p1_to_p3(Rv, Rp1p1);

            // Check h == SHA512(label(4) || A || V || R || Rv || M) 
            m[0] = 0xFB; // label 4
            for (count = 1; count < 32; count++)
            {
                m[count] = 0xFF;
            }
            Array.Copy(pk, 0, m, 32, 32);
            byte[] M = new byte[32];
            Array.Copy(m, 64, M, 0, 32);
            Ge_p3_tobytes.ge_p3_tobytes(M, V);
            Array.Copy(M, 0, m, 64, 32);
            byte[] M2 = new byte[32];
            Array.Copy(m, 96, M2, 0, 32);
            Ge_tobytes.ge_tobytes(M2, R);
            Array.Copy(M2, 0, m, 96, 32);
            byte[] M3 = new byte[32];
            Array.Copy(m, 128, M3, 0, 32);
            Ge_p3_tobytes.ge_p3_tobytes(M3, Rv);
            Array.Copy(M3, 0, m, 128, 32);
            Array.Copy(sm, 96, m, 160, (int)smlen - 96);

            sha512provider.calculateDigest(hcheck, m, smlen + 64);
            Sc_reduce.sc_reduce(hcheck);

            if (Crypto_verify_32.crypto_verify_32(hcheck, h) == 0)
            {
                byte[] M4 = new byte[32];
                Array.Copy(m, 32, M4, 0, 32);
                Ge_p3_tobytes.ge_p3_tobytes(M4, c_V);
                Array.Copy(M4, 0, m, 32, 32);
                m[0] = 0xFA; // label 5
                sha512provider.calculateDigest(vrf_output, m, 64);
                Array.Copy(vrf_output, 0, m, 0, 32);
                return 0;
            }

            //badsig
            //memset(m, 0, 32);
            return -1;
        }
    }
}
