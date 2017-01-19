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
    public class usign_modified
    {
        public static int crypto_usign_modified(ISha512 sha512provider,
            byte[] sm,
            byte[] M, int Mlen,
            byte[] a,
            byte[] A,
            byte[] random,
            Ge_p3 Bu,
            byte[] U)
        {
            byte[] r = new byte[64];
            byte[] h = new byte[64];
            Ge_p3 R = new Ge_p3();
            Ge_p3 Ru = new Ge_p3();
            int count = 0;

            /* r = SHA512(label(3) || a || U || random(64)) */
            sm[0] = 0xFC;
            for (count = 1; count < 32; count++)
            {
                sm[count] = 0xFF;
            }

            Array.Copy(a, 0, sm, 32, 32); /* Use privkey directly for nonce derivation */
            Array.Copy(U, 0, sm, 64, 32);

            Array.Copy(random, 0, sm, 96, 64); /* Add suffix of random data */
            sha512provider.calculateDigest(r, sm, 160);

            Sc_reduce.sc_reduce(r);
            Ge_scalarmult_base.ge_scalarmult_base(R, r);
            Ge_scalarmult.ge_scalarmult(Ru, r, Bu);

            /* h = SHA512(label(4) || A || U || R || Ru || M) */
            sm[0] = 0xFB;
            Array.Copy(A, 0, sm, 32, 32);
            Array.Copy(U, 0, sm, 64, 32);
            byte[] S = new byte[32];
            Array.Copy(sm, 96, S, 0, 32);
            Ge_p3_tobytes.ge_p3_tobytes(S, R);
            Array.Copy(S, 0, sm, 96, 32);
            byte[] S2 = new byte[32];
            Array.Copy(sm, 128, S2, 0, 32);
            Ge_p3_tobytes.ge_p3_tobytes(S2, Ru);
            Array.Copy(S2, 0, sm, 128, 32);
            Array.Copy(M, 0, sm, 160, Mlen);

            sha512provider.calculateDigest(h, sm, Mlen + 160);
            Sc_reduce.sc_reduce(h);

            Array.Copy(h, 0, sm, 0, 32); /* Write h */
            byte[] S3 = new byte[32];
            Array.Copy(sm, 32, S3, 0, 32);
            Sc_muladd.sc_muladd(S3, h, a, r);
            Array.Copy(S3, 0, sm, 32, 32);

            /* Erase any traces of private scalar or
             * nonce left in the stack from sc_muladd. */
            //zeroize_stack();
            Zeroize.zeroize(r, 64);
            return 0;
        }
    }
}
