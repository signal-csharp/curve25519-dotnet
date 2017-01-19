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

    public class Fe_add
    {

        //CONVERT #include "fe.h"

        /*
        h = f + g
        Can overlap h with f or g.

        Preconditions:
           |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
           |g| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.

        Postconditions:
           |h| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
        */

        public static void fe_add(int[] h, int[] f, int[] g)
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
            int g0 = g[0];
            int g1 = g[1];
            int g2 = g[2];
            int g3 = g[3];
            int g4 = g[4];
            int g5 = g[5];
            int g6 = g[6];
            int g7 = g[7];
            int g8 = g[8];
            int g9 = g[9];
            int h0 = f0 + g0;
            int h1 = f1 + g1;
            int h2 = f2 + g2;
            int h3 = f3 + g3;
            int h4 = f4 + g4;
            int h5 = f5 + g5;
            int h6 = f6 + g6;
            int h7 = f7 + g7;
            int h8 = f8 + g8;
            int h9 = f9 + g9;
            h[0] = (int)h0;
            h[1] = (int)h1;
            h[2] = (int)h2;
            h[3] = (int)h3;
            h[4] = (int)h4;
            h[5] = (int)h5;
            h[6] = (int)h6;
            h[7] = (int)h7;
            h[8] = (int)h8;
            h[9] = (int)h9;
        }


    }
}
