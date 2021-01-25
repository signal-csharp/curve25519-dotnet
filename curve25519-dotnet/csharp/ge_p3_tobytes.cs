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

namespace org.whispersystems.curve25519.csharp
{

    public class Ge_p3_tobytes
    {

        //CONVERT #include "ge.h"

        public static void ge_p3_tobytes(byte[] s, Ge_p3 h)
        {
            int[] recip = new int[10];
            int[] x = new int[10];
            int[] y = new int[10];

            Fe_invert.fe_invert(recip, h.Z);
            Fe_mul.fe_mul(x, h.X, recip);
            Fe_mul.fe_mul(y, h.Y, recip);
            Fe_tobytes.fe_tobytes(s, y);
            s[31] ^= (byte)(Fe_isnegative.fe_isnegative(x) << 7);
        }
    }
}
