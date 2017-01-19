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

    public class Ge_p3_to_p2
    {

        //CONVERT #include "ge.h"

        /*
        r = p
        */

        public static void ge_p3_to_p2(Ge_p2 r, Ge_p3 p)
        {
            Fe_copy.fe_copy(r.X, p.X);
            Fe_copy.fe_copy(r.Y, p.Y);
            Fe_copy.fe_copy(r.Z, p.Z);
        }
    }
}
