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
    public class Vsign_modified
    {
        public static int crypto_vsign_modified(ISha512 sha512provider,
            byte[] sm,
            byte[] M, int Mlen,
            byte[] a,
            byte[] A,
            byte[] random,
            Ge_p3 Bv,
            byte[] V)
        {
            byte[] r = new byte[64];
            byte[] h = new byte[64];
            Ge_p3 R = new Ge_p3();
            Ge_p3 Rv = new Ge_p3();
            int count = 0;

            /* r = SHA512(label(3) || a || V || random(64)) */
            sm[0] = 0xFC;
            for (count = 1; count < 32; count++)
            {
                sm[count] = 0xFF;
            }

            Array.Copy(a, 0, sm, 32, 32); /* Use privkey directly for nonce derivation */
            Array.Copy(V, 0, sm, 64, 32);

            Array.Copy(random, 0, sm, 96, 64); /* Add suffix of random data */
            sha512provider.calculateDigest(r, sm, 160);

            Sc_reduce.sc_reduce(r);
            Ge_scalarmult_base.ge_scalarmult_base(R, r);
            Ge_scalarmult.ge_scalarmult(Rv, r, Bv);

            /* h = SHA512(label(4) || A || V || R || Rv || M) */
            sm[0] = 0xFB;
            Array.Copy(A, 0, sm, 32, 32);
            Array.Copy(V, 0, sm, 64, 32);
            byte[] R1 = new byte[32];
            Array.Copy(sm, 96, R1, 0, 32);
            Ge_p3_tobytes.ge_p3_tobytes(R1, R);
            Array.Copy(R1, 0, sm, 96, 32);
            byte[] R2 = new byte[32];
            Array.Copy(sm, 128, R2, 0, 32);
            Ge_p3_tobytes.ge_p3_tobytes(R2, Rv);
            Array.Copy(R2, 0, sm, 128, 32);
            Array.Copy(M, 0, sm, 160, Mlen);

            sha512provider.calculateDigest(h, sm, Mlen + 160);
            Sc_reduce.sc_reduce(h);

            Array.Copy(h, 0, sm, 0, 32);
            byte[] S = new byte[32];
            Array.Copy(sm, 32, S, 0, 32);
            Sc_muladd.sc_muladd(S, h, a, r);
            Array.Copy(S, 0, sm, 32, 32);

            /* Erase any traces of private scalar or
               nonce left in stack from sc_muladd. */
            //zeroize_stack();
            Zeroize.zeroize(r, 64);
            return 0;
        }
    }
}
