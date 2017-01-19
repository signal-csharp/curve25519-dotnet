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

    public class Fe_copy
    {

        //CONVERT #include "fe.h"

        /*
        h = f
        */

        public static void fe_copy(int[] h, int[] f)
        {
            int f0 = f[0];
            int f1 = f[1];
            int f2 = f[2];
            int f3 = f[3];
            int f4 = f[4];
            int f5 = f[5];
            int f6 = f[6];
            int f7 = f[7];
            int f8 = f[8];
            int f9 = f[9];
            h[0] = f0;
            h[1] = f1;
            h[2] = f2;
            h[3] = f3;
            h[4] = f4;
            h[5] = f5;
            h[6] = f6;
            h[7] = f7;
            h[8] = f8;
            h[9] = f9;
        }


    }
}
