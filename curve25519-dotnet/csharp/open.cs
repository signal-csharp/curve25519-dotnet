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

    public class Open
    {

        //CONVERT #include <string.h>
        //CONVERT #include "crypto_sign.h"
        //CONVERT #include "crypto_hash_sha512.h"
        //CONVERT #include "crypto_verify_32.h"
        //CONVERT #include "ge.h"
        //CONVERT #include "sc.h"

        public static int crypto_sign_open(
          ISha512 sha512provider,
          byte[] m, long mlen,
          byte[] sm, long smlen,
          byte[] pk
        )
        {
            byte[] pkcopy = new byte[32];
            byte[] rcopy = new byte[32];
            byte[] scopy = new byte[32];
            byte[] h = new byte[64];
            byte[] rcheck = new byte[32];
            Ge_p3 A = new Ge_p3();
            Ge_p2 R = new Ge_p2();

            if (smlen < 64) return -1;
            if ((sm[63] & 224) != 0) return -1;
            if (Ge_frombytes.ge_frombytes_negate_vartime(A, pk) != 0) return -1;

            byte[] pubkeyhash = new byte[64];
            sha512provider.calculateDigest(pubkeyhash, pk, 32);

            Array.Copy(pk, 0, pkcopy, 0, 32);
            Array.Copy(sm, 0, rcopy, 0, 32);
            Array.Copy(sm, 32, scopy, 0, 32);

            Array.Copy(sm, 0, m, 0, (int)smlen);
            Array.Copy(pkcopy, 0, m, 32, 32);
            sha512provider.calculateDigest(h, m, smlen);
            Sc_reduce.sc_reduce(h);

            Ge_double_scalarmult.ge_double_scalarmult_vartime(R, h, A, scopy);
            Ge_tobytes.ge_tobytes(rcheck, R);
            if (Crypto_verify_32.crypto_verify_32(rcheck, rcopy) == 0)
            {
                Array.Copy(m, 64, m, 0, (int)(smlen - 64));
                //memset(m + smlen - 64,0,64);
                return 0;
            }

            //badsig:
            //memset(m,0,smlen);
            return -1;
        }


    }
}
