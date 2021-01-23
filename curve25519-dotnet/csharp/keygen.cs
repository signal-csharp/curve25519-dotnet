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
    public class Keygen
    {
        public static void curve25519_keygen(Span<byte> curve25519_pubkey_out, ReadOnlySpan<byte> curve25519_privkey_in)
        {
            /* Perform a fixed-base multiplication of the Edwards base point,
             * (which is efficient due to precalculated tables), then convert
             * to the Curve25519 montgomery-format public key.
             * 
             * NOTE: y=1 is converted to u=0 since fe_invert is mod-exp 
             */

            Ge_p3 ed = new Ge_p3(); /* Ed25519 pubkey point */
            int[] u = new int[10];

            Ge_scalarmult_base.ge_scalarmult_base(ed, curve25519_privkey_in);
            Ge_p3_to_montx.ge_p3_to_montx(u, ed);
            Fe_tobytes.fe_tobytes(curve25519_pubkey_out, u);
        }
    }
}
