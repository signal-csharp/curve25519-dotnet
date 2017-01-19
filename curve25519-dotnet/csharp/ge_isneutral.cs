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

namespace org.whispersystems.curve25519.csharp
{
    public class Ge_isneutral
    {
        /*
         * return 1 if p is the neutral point
         * return 0 otherwise
         */

        public static int ge_isneutral(Ge_p3 p)
        {
            int[] zero = new int[10];
            Fe_0.fe_0(zero);

            /* Check if p == neutral element == (0, 1) */
            return (Fe_isequal.fe_isequal(p.X, zero) & Fe_isequal.fe_isequal(p.Y, p.Z));
        }
    }
}
