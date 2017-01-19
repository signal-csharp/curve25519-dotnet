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
    public class Fe_montx_to_edy
    {
        public static void fe_montx_to_edy(int[] y, int[] u)
        {
            /*
             * y = (u - 1) / (u + 1)
             * 
             * NOTE: u=-1 is converted to y=0 since fe_invert is mod-exp
             */

            int[] one = new int[10];
            int[] um1 = new int[10];
            int[] up1 = new int[10];

            Fe_1.fe_1(one);
            Fe_sub.fe_sub(um1, u, one);
            Fe_add.fe_add(up1, u, one);
            Fe_invert.fe_invert(up1, up1);
            Fe_mul.fe_mul(y, um1, up1);
        }
    }
}
