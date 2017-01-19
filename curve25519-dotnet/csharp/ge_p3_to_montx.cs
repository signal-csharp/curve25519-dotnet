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

namespace org.whispersystems.curve25519.csharp
{
    public class Ge_p3_to_montx
    {
        public static void ge_p3_to_montx(int[] u, Ge_p3 ed)
        {
            /*
             * u = (y + 1) / (1 - y)
             * or
             * u = (y + z) / (z - y)
             * 
             * NOTE: y=1 is converted to u=0 since fe_invert is mod-exp
             */

            int[] y_plus_one = new int[10];
            int[] one_minus_y = new int[10];
            int[] inv_one_minus_y = new int[10];

            Fe_add.fe_add(y_plus_one, ed.Y, ed.Z);
            Fe_sub.fe_sub(one_minus_y, ed.Z, ed.Y);
            Fe_invert.fe_invert(inv_one_minus_y, one_minus_y);
            Fe_mul.fe_mul(u, y_plus_one, inv_one_minus_y);
        }
    }
}
