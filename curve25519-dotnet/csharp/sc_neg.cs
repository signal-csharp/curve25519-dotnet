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
    public class Sc_neg
    {
        /* l = order of base point = 2^252 + 27742317777372353535851937790883648493 */

        /*
         * static unsigned char l[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
         *                               0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
         *                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         *                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0, 0x10};
         */

        private static byte[] lminus1 = new byte[]
        {
            0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
        };

        /* b = -a (mod l) */
        public static void sc_neg(Span<byte> b, ReadOnlySpan<byte> a)
        {
            ReadOnlySpan<byte> zero = new ReadOnlySpan<byte>(new byte[32]);
            //memset(zero, 0, 32);
            Sc_muladd.sc_muladd(b, lminus1, a, zero); /* b = (-1)a + 0   (mod l) */
        }
    }
}
