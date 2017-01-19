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

    public class Ge_p3_to_cached
    {

        //CONVERT #include "ge.h"

        /*
        r = p
        */

        static int[] d2 = {
//CONVERT #include "d2.h"
-21827239,-5839606,-30745221,13898782,229458,15978800,-12551817,-6495438,29715968,9444199
};

        public static void ge_p3_to_cached(Ge_cached r, Ge_p3 p)
        {
            Fe_add.fe_add(r.YplusX, p.Y, p.X);
            Fe_sub.fe_sub(r.YminusX, p.Y, p.X);
            Fe_copy.fe_copy(r.Z, p.Z);
            Fe_mul.fe_mul(r.T2d, p.T, d2);
        }
    }
}
