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
    public class Ge_scalarmult_cofactor
    {
        /*
         * return 8 * p
         */
        
        public static void ge_scalarmult_cofactor(Ge_p3 q, Ge_p3 p)
        {
            Ge_p1p1 p1p1 = new Ge_p1p1();
            Ge_p2 p2 = new Ge_p2();

            Ge_p3_dbl.ge_p3_dbl(p1p1, p);
            Ge_p1p1_to_p2.ge_p1p1_to_p2(p2, p1p1);

            Ge_p2_dbl.ge_p2_dbl(p1p1, p2);
            Ge_p1p1_to_p2.ge_p1p1_to_p2(p2, p1p1);

            Ge_p2_dbl.ge_p2_dbl(p1p1, p2);
            Ge_p1p1_to_p3.ge_p1p1_to_p3(q, p1p1);
        }
    }
}
