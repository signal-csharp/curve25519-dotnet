﻿/** 
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

    public class Ge_double_scalarmult
    {
        /// <summary>
        /// DEBUG
        /// </summary>
        public static string ByteArrayToString(byte[] ba)
        {
            System.Text.StringBuilder hex = new System.Text.StringBuilder(ba.Length * 2);
            int i = 0;
            foreach (byte b in ba)
            {
                hex.AppendFormat("[{0}] => ", i);
                hex.AppendFormat("0x{0:x}, ", b);
                i++;
            }
                
            return hex.ToString();
        }

        //CONVERT #include "ge.h"

        public static void slide(sbyte[] r, byte[] a)
        {
            int i;
            int b;
            int k;

            for (i = 0; i < 256; ++i)
            {
                r[i] = (sbyte)(1 & (sbyte)(((uint)(a[i >> 3])) >> (i & 7)));
            }

            for (i = 0; i < 256; ++i)
                if (r[i] != 0)
                {
                    for (b = 1; b <= 6 && i + b < 256; ++b)
                    {
                        if (r[i + b] != 0)
                        {
                            if (r[i] + (r[i + b] << b) <= 15)
                            {
                                r[i] += (sbyte)(r[i + b] << b);
                                r[i + b] = 0;
                            }
                            else if (r[i] - (r[i + b] << b) >= -15)
                            {
                                r[i] -= (sbyte)(r[i + b] << b);
                                for (k = i + b; k < 256; ++k)
                                {
                                    if (r[k] == 0)
                                    {
                                        r[k] = 1;
                                        break;
                                    }
                                    r[k] = 0;
                                }
                            }
                            else
                                break;
                        }
                    }
                }

        }

        public static Ge_precomp[] Bi;

        static Ge_double_scalarmult()
        {
            Bi = new Ge_precomp[8];
            Bi[0] = new Ge_precomp(
            new int[] { 25967493, -14356035, 29566456, 3660896, -12694345, 4014787, 27544626, -11754271, -6079156, 2047605 },
            new int[] { -12545711, 934262, -2722910, 3049990, -727428, 9406986, 12720692, 5043384, 19500929, -15469378 },
            new int[] { -8738181, 4489570, 9688441, -14785194, 10184609, -12363380, 29287919, 11864899, -24514362, -4438546 }
            );
            Bi[1] = new Ge_precomp(
            new int[] { 15636291, -9688557, 24204773, -7912398, 616977, -16685262, 27787600, -14772189, 28944400, -1550024 },
            new int[] { 16568933, 4717097, -11556148, -1102322, 15682896, -11807043, 16354577, -11775962, 7689662, 11199574 },
            new int[] { 30464156, -5976125, -11779434, -15670865, 23220365, 15915852, 7512774, 10017326, -17749093, -9920357 }
            );
            Bi[2] = new Ge_precomp(
            new int[] { 10861363, 11473154, 27284546, 1981175, -30064349, 12577861, 32867885, 14515107, -15438304, 10819380 },
            new int[] { 4708026, 6336745, 20377586, 9066809, -11272109, 6594696, -25653668, 12483688, -12668491, 5581306 },
            new int[] { 19563160, 16186464, -29386857, 4097519, 10237984, -4348115, 28542350, 13850243, -23678021, -15815942 }
            );
            Bi[3] = new Ge_precomp(
            new int[] { 5153746, 9909285, 1723747, -2777874, 30523605, 5516873, 19480852, 5230134, -23952439, -15175766 },
            new int[] { -30269007, -3463509, 7665486, 10083793, 28475525, 1649722, 20654025, 16520125, 30598449, 7715701 },
            new int[] { 28881845, 14381568, 9657904, 3680757, -20181635, 7843316, -31400660, 1370708, 29794553, -1409300 }
            );
            Bi[4] = new Ge_precomp(
            new int[] { -22518993, -6692182, 14201702, -8745502, -23510406, 8844726, 18474211, -1361450, -13062696, 13821877 },
            new int[] { -6455177, -7839871, 3374702, -4740862, -27098617, -10571707, 31655028, -7212327, 18853322, -14220951 },
            new int[] { 4566830, -12963868, -28974889, -12240689, -7602672, -2830569, -8514358, -10431137, 2207753, -3209784 }
            );
            Bi[5] = new Ge_precomp(
            new int[] { -25154831, -4185821, 29681144, 7868801, -6854661, -9423865, -12437364, -663000, -31111463, -16132436 },
            new int[] { 25576264, -2703214, 7349804, -11814844, 16472782, 9300885, 3844789, 15725684, 171356, 6466918 },
            new int[] { 23103977, 13316479, 9739013, -16149481, 817875, -15038942, 8965339, -14088058, -30714912, 16193877 }
            );
            Bi[6] = new Ge_precomp(
            new int[] { -33521811, 3180713, -2394130, 14003687, -16903474, -16270840, 17238398, 4729455, -18074513, 9256800 },
            new int[] { -25182317, -4174131, 32336398, 5036987, -21236817, 11360617, 22616405, 9761698, -19827198, 630305 },
            new int[] { -13720693, 2639453, -24237460, -7406481, 9494427, -5774029, -6554551, -15960994, -2449256, -14291300 }
            );
            Bi[7] = new Ge_precomp(
            new int[] { -3151181, -5046075, 9282714, 6866145, -31907062, -863023, -18940575, 15033784, 25105118, -7894876 },
            new int[] { -24326370, 15950226, -31801215, -14592823, -11662737, -5090925, 1573892, -2625887, 2198790, -15804619 },
            new int[] { -3099351, 10324967, -2241613, 7453183, -5446979, -2735503, -13812022, -16236442, -32461234, -12290683 }
            );
        }

        /*
        r = a * A + b * B
        where a = a[0]+256*a[1]+...+256^31 a[31].
        and b = b[0]+256*b[1]+...+256^31 b[31].
        B is the Ed25519 base point (x,4/5) with x positive.
        */

        public static void ge_double_scalarmult_vartime(Ge_p2 r, byte[] a, Ge_p3 A, byte[] b)
        {
            sbyte[] aslide = new sbyte[256];
            sbyte[] bslide = new sbyte[256];
            Ge_cached[] Ai = new Ge_cached[8]; /* A,3A,5A,7A,9A,11A,13A,15A */
            for (int count = 0; count < 8; count++)
                Ai[count] = new Ge_cached();
            Ge_p1p1 t = new Ge_p1p1();
            Ge_p3 u = new Ge_p3();
            Ge_p3 A2 = new Ge_p3();
            int i;

            slide(aslide, a);
            slide(bslide, b);

            Ge_p3_to_cached.ge_p3_to_cached(Ai[0], A);
            Ge_p3_dbl.ge_p3_dbl(t, A); Ge_p1p1_to_p3.ge_p1p1_to_p3(A2, t);
            Ge_add.ge_add(t, A2, Ai[0]); Ge_p1p1_to_p3.ge_p1p1_to_p3(u, t); Ge_p3_to_cached.ge_p3_to_cached(Ai[1], u);
            Ge_add.ge_add(t, A2, Ai[1]); Ge_p1p1_to_p3.ge_p1p1_to_p3(u, t); Ge_p3_to_cached.ge_p3_to_cached(Ai[2], u);
            Ge_add.ge_add(t, A2, Ai[2]); Ge_p1p1_to_p3.ge_p1p1_to_p3(u, t); Ge_p3_to_cached.ge_p3_to_cached(Ai[3], u);
            Ge_add.ge_add(t, A2, Ai[3]); Ge_p1p1_to_p3.ge_p1p1_to_p3(u, t); Ge_p3_to_cached.ge_p3_to_cached(Ai[4], u);
            Ge_add.ge_add(t, A2, Ai[4]); Ge_p1p1_to_p3.ge_p1p1_to_p3(u, t); Ge_p3_to_cached.ge_p3_to_cached(Ai[5], u);
            Ge_add.ge_add(t, A2, Ai[5]); Ge_p1p1_to_p3.ge_p1p1_to_p3(u, t); Ge_p3_to_cached.ge_p3_to_cached(Ai[6], u);
            Ge_add.ge_add(t, A2, Ai[6]); Ge_p1p1_to_p3.ge_p1p1_to_p3(u, t); Ge_p3_to_cached.ge_p3_to_cached(Ai[7], u);

            Ge_p2_0.ge_p2_0(r);

            for (i = 255; i >= 0; --i)
            {
                if (aslide[i] != 0 || bslide[i] != 0) break;
            }

            for (; i >= 0; --i)
            {
                Ge_p2_dbl.ge_p2_dbl(t, r);

                if (aslide[i] > 0)
                {
                    Ge_p1p1_to_p3.ge_p1p1_to_p3(u, t);
                    Ge_add.ge_add(t, u, Ai[aslide[i] / 2]);
                }
                else if (aslide[i] < 0)
                {
                    Ge_p1p1_to_p3.ge_p1p1_to_p3(u, t);
                    Ge_sub.ge_sub(t, u, Ai[(-aslide[i]) / 2]);
                }

                if (bslide[i] > 0)
                {
                    Ge_p1p1_to_p3.ge_p1p1_to_p3(u, t);
                    Ge_madd.ge_madd(t, u, Bi[bslide[i] / 2]);
                }
                else if (bslide[i] < 0)
                {
                    Ge_p1p1_to_p3.ge_p1p1_to_p3(u, t);
                    Ge_msub.ge_msub(t, u, Bi[(-bslide[i]) / 2]);
                }

                Ge_p1p1_to_p2.ge_p1p1_to_p2(r, t);
            }
        }


    }
}
