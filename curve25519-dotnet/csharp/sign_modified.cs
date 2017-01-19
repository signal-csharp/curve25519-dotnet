/** 
 * Copyright (C) 2016 langboost, golf1052
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

    public class sign_modified
    {

        //CONVERT #include <string.h>
        //CONVERT #include "crypto_sign.h"
        //CONVERT #include "crypto_hash_sha512.h"
        //CONVERT #include "ge.h"
        //CONVERT #include "sc.h"
        //CONVERT #include "zeroize.h"

        /* NEW: Compare to pristine crypto_sign() 
           Uses explicit private key for nonce derivation and as scalar,
           instead of deriving both from a master key.
        */
        public static int crypto_sign_modified(
          ISha512 sha512provider,
          byte[] sm,
          byte[] m, long mlen,
          byte[] sk, byte[] pk,
          byte[] random
        )
        {
            byte[] nonce = new byte[64];
            byte[] hram = new byte[64];
            Ge_p3 R = new Ge_p3();
            int count = 0;

            Array.Copy(m, 0, sm, 64, (int)mlen);
            Array.Copy(sk, 0, sm, 32, 32);

            /* NEW : add prefix to separate hash uses - see .h */
            sm[0] = (byte)0xFE;
            for (count = 1; count < 32; count++)
                sm[count] = (byte)0xFF;

            /* NEW: add suffix of random data */
            Array.Copy(random, 0, sm, (int)(mlen + 64), 64);

            sha512provider.calculateDigest(nonce, sm, mlen + 128);
            Array.Copy(pk, 0, sm, 32, 32);

            Sc_reduce.sc_reduce(nonce);
            Ge_scalarmult_base.ge_scalarmult_base(R, nonce);
            Ge_p3_tobytes.ge_p3_tobytes(sm, R);

            sha512provider.calculateDigest(hram, sm, mlen + 64);
            Sc_reduce.sc_reduce(hram);
            byte[] S = new byte[32];
            Sc_muladd.sc_muladd(S, hram, sk, nonce); /* NEW: Use privkey directly */
            Array.Copy(S, 0, sm, 32, 32);

            /* Erase any traces of private scalar or
             * nonce left in the stack from sc_muladd */
            //zeroize_stack();
            Zeroize.zeroize(nonce, 64);
            return 0;
        }


    }
}
