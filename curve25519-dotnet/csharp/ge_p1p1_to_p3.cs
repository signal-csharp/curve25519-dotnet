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

    public class Ge_p1p1_to_p3
    {

        //CONVERT #include "ge.h"

        /*
        r = p
        */

        public static void ge_p1p1_to_p3(Ge_p3 r, Ge_p1p1 p)
        {
            Fe_mul.fe_mul(r.X, p.X, p.T);
            Fe_mul.fe_mul(r.Y, p.Y, p.Z);
            Fe_mul.fe_mul(r.Z, p.Z, p.T);
            Fe_mul.fe_mul(r.T, p.X, p.Y);
        }


    }
}
