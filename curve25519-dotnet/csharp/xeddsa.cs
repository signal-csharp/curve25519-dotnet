

using curve25519_dotnet.csharp;
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
    public class xeddsa
    {
        public static int xed25519_sign(ISha512 sha512provider,
            byte[] signature_out,
            byte[] curve25519_privkey,
            byte[] msg, int msg_len,
            byte[] random)
        {
            byte[] a = new byte[32];
            byte[] A = new byte[32];
            byte[] aneg = new byte[32];
            Ge_p3 ed_pubkey_point = new Ge_p3();
            // see link below
            byte[] sigbuf = new byte[msg_len + 128]; /* working buffer */
            byte sign_bit = 0;

            // this should be different but whatever
            // https://github.com/WhisperSystems/curve25519-java/commit/2f388f601afdac6a78a19ced2f0629da1ff9800f#diff-6e488e4e28814b3fa524b6781fcaf912R19
            //if (msg_len > crypto_additions.MAX_MSG_LEN)
            //{
            //    //memset(signature_out, 0, 64);
            //    return -1;
            //}

            /* Convert the Curve25519 privkey to an Ed25519 public key */
            Ge_scalarmult_base.ge_scalarmult_base(ed_pubkey_point, curve25519_privkey);
            Ge_p3_tobytes.ge_p3_tobytes(A, ed_pubkey_point);

            /* Force Edwards sign bit to zero */
            sign_bit = (byte)((A[31] & 0x80) >> 7);
            Array.Copy(curve25519_privkey, 0, a, 0, 32);
            Sc_neg.sc_neg(aneg, a);
            Sc_cmov.sc_cmov(a, aneg, sign_bit);
            A[31] &= 0x7F;

            /* Perform an Ed25519 signature with explicit private key */
            sign_modified.crypto_sign_modified(sha512provider, sigbuf, msg, msg_len, a, A, random);
            Array.Copy(sigbuf, 0, signature_out, 0, 64);

            Zeroize.zeroize(a, 32);
            Zeroize.zeroize(aneg, 32);
            return 0;
        }

        public static int xed25519_verify(ISha512 sha512provider, byte[] signature, byte[] curve25519_pubkey, byte[] msg, int msg_len)
        {
            int[] u = new int[10];
            int[] y = new int[10];
            byte[] ed_pubkey = new byte[32];
            byte[] verifybuf = new byte[crypto_additions.MAX_MSG_LEN + 64]; /* working buffer */
            byte[] verifybuf2 = new byte[crypto_additions.MAX_MSG_LEN + 64]; /* working buffer #2 */

            if (msg_len > crypto_additions.MAX_MSG_LEN)
            {
                return -1;
            }

            /* Convert the Curve25519 public key into an Ed25519 public key.
             * 
             * y = (u - 1) / (u + 1)
             * 
             * NOTE: u=-1 is converted to y=0 since fe_invert is mod-exp
             */
            if (!Fe_isreduced.fe_isreduced(curve25519_pubkey))
                return -1;
            Fe_frombytes.fe_frombytes(u, curve25519_pubkey);
            Fe_montx_to_edy.fe_montx_to_edy(y, u);
            Fe_tobytes.fe_tobytes(ed_pubkey, y);

            Array.Copy(signature, 0, verifybuf, 0, 64);
            Array.Copy(msg, 0, verifybuf, 64, msg_len);

            /* Then perform a normal Ed25519 verification, return 0 on success */
            /* The below call has a strange API: */
            /* verifybuf = R || S || message */
            /* verifybuf2 = internal to next call gets a copy of verifybuf, S gets
             replaced with pubkey for hashing*/
            return open_modified.crypto_sign_open_modified(sha512provider, verifybuf2, verifybuf, 64 + msg_len, ed_pubkey);
        }
    }
}
