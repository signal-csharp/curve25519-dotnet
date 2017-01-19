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
    public class Ge_neg
    {
        /*
         * return r = -p
         */
        
        public static void ge_neg(Ge_p3 r, Ge_p3 p)
        {
            Fe_neg.fe_neg(r.X, p.X);
            Fe_copy.fe_copy(r.Y, p.Y);
            Fe_copy.fe_copy(r.Z, p.Z);
            Fe_neg.fe_neg(r.T, p.T);
        }
    }
}
