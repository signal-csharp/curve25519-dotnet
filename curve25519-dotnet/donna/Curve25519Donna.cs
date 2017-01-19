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

using System;
using Limb = System.Int64;
using S32 = System.Int32;

//C# port of Google's curve25519-donna public key function
//Author: langboost
//Original copyright notice from Google is below.

/* Copyright 2008, Google Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * curve25519-donna: Curve25519 elliptic curve, public key function
 *
 * http://code.google.com/p/curve25519-donna/
 *
 * Adam Langley <agl@imperialviolet.org>
 *
 * Derived from public domain C code by Daniel J. Bernstein <djb@cr.yp.to>
 *
 * More information about curve25519 can be found here
 *   http://cr.yp.to/ecdh.html
 *
 * djb's sample implementation of curve25519 is written in a special assembly
 * language called qhasm and uses the floating point registers.
 *
 * This is, almost, a clean room reimplementation from the curve25519 paper. It
 * uses many of the tricks described therein. Only the crecip function is taken
 * from the sample implementation. */

namespace curve25519.donna
{
    public static class Curve25519Donna
    {
        /// <summary>
        /// Sum two short form numbers: output += in
        /// </summary>
        public static void fsum(Limb[] output, Limb[] input)
        {
            for (int i = 0; i < 10; i += 2)
            {
                output[0 + i] = output[0 + i] + input[0 + i];
                output[1 + i] = output[1 + i] + input[1 + i];
            }
        }

        /// <summary>
        /// Find the difference of two numbers: output = in - output (note the order of the arguments!).
        /// </summary>
        public static void fdifference(Limb[] output, Limb[] input)
        {
            for (int i = 0; i < 10; ++i)
            {
                output[i] = input[i] - output[i];
            }
        }

        /// <summary>
        /// Multiply a number by a scalar: output = in * scalar
        /// </summary>
        public static void fscalar_product(Limb[] output, Limb[] input, Limb scalar)
        {
            for (int i = 0; i < 10; ++i)
            {
                output[i] = input[i] * scalar;
            }
        }

        /// <summary>
        /// Multiply two numbers: output = in2 * in
        /// output must be distinct to both inputs. The inputs are reduced coefficient
        /// form, the output is not.
        /// 
        /// output[x] &lt;= 14 * the largest product of the input limbs.
        /// </summary>
        public static void fproduct(Limb[] output, Limb[] in2, Limb[] input)
        {
            output[0] =
                ((Limb)((S32)in2[0])) * ((S32)input[0]);
            output[1] =
                ((Limb)((S32)in2[0])) * ((S32)input[1]) +
                ((Limb)((S32)in2[1])) * ((S32)input[0]);
            output[2] = 2 *
                ((Limb)((S32)in2[1])) * ((S32)input[1]) +
                ((Limb)((S32)in2[0])) * ((S32)input[2]) +
                ((Limb)((S32)in2[2])) * ((S32)input[0]);
            output[3] =
                ((Limb)((S32)in2[1])) * ((S32)input[2]) +
                ((Limb)((S32)in2[2])) * ((S32)input[1]) +
                ((Limb)((S32)in2[0])) * ((S32)input[3]) +
                ((Limb)((S32)in2[3])) * ((S32)input[0]);
            output[4] =
                ((Limb)((S32)in2[2])) * ((S32)input[2]) +
                2 *
                    (((Limb)((S32)in2[1])) * ((S32)input[3]) +
                    ((Limb)((S32)in2[3])) * ((S32)input[1])) +
                ((Limb)((S32)in2[0])) * ((S32)input[4]) +
                ((Limb)((S32)in2[4])) * ((S32)input[0]);
            output[5] =
                ((Limb)((S32)in2[2])) * ((S32)input[3]) +
                ((Limb)((S32)in2[3])) * ((S32)input[2]) +
                ((Limb)((S32)in2[1])) * ((S32)input[4]) +
                ((Limb)((S32)in2[4])) * ((S32)input[1]) +
                ((Limb)((S32)in2[0])) * ((S32)input[5]) +
                ((Limb)((S32)in2[5])) * ((S32)input[0]);
            output[6] =
                2 *
                    (((Limb)((S32)in2[3])) * ((S32)input[3]) +
                    ((Limb)((S32)in2[1])) * ((S32)input[5]) +
                    ((Limb)((S32)in2[5])) * ((S32)input[1])) +
                ((Limb)((S32)in2[2])) * ((S32)input[4]) +
                ((Limb)((S32)in2[4])) * ((S32)input[2]) +
                ((Limb)((S32)in2[0])) * ((S32)input[6]) +
                ((Limb)((S32)in2[6])) * ((S32)input[0]);
            output[7] =
                ((Limb)((S32)in2[3])) * ((S32)input[4]) +
                ((Limb)((S32)in2[4])) * ((S32)input[3]) +
                ((Limb)((S32)in2[2])) * ((S32)input[5]) +
                ((Limb)((S32)in2[5])) * ((S32)input[2]) +
                ((Limb)((S32)in2[1])) * ((S32)input[6]) +
                ((Limb)((S32)in2[6])) * ((S32)input[1]) +
                ((Limb)((S32)in2[0])) * ((S32)input[7]) +
                ((Limb)((S32)in2[7])) * ((S32)input[0]);
            output[8] =
                ((Limb)((S32)in2[4])) * ((S32)input[4]) +
                2 * (((Limb)((S32)in2[3])) * ((S32)input[5]) +
                    ((Limb)((S32)in2[5])) * ((S32)input[3]) +
                    ((Limb)((S32)in2[1])) * ((S32)input[7]) +
                    ((Limb)((S32)in2[7])) * ((S32)input[1])) +
                ((Limb)((S32)in2[2])) * ((S32)input[6]) +
                ((Limb)((S32)in2[6])) * ((S32)input[2]) +
                ((Limb)((S32)in2[0])) * ((S32)input[8]) +
                ((Limb)((S32)in2[8])) * ((S32)input[0]);
            output[9] =
                ((Limb)((S32)in2[4])) * ((S32)input[5]) +
                ((Limb)((S32)in2[5])) * ((S32)input[4]) +
                ((Limb)((S32)in2[3])) * ((S32)input[6]) +
                ((Limb)((S32)in2[6])) * ((S32)input[3]) +
                ((Limb)((S32)in2[2])) * ((S32)input[7]) +
                ((Limb)((S32)in2[7])) * ((S32)input[2]) +
                ((Limb)((S32)in2[1])) * ((S32)input[8]) +
                ((Limb)((S32)in2[8])) * ((S32)input[1]) +
                ((Limb)((S32)in2[0])) * ((S32)input[9]) +
                ((Limb)((S32)in2[9])) * ((S32)input[0]);
            output[10] =
                2 * (((Limb)((S32)in2[5])) * ((S32)input[5]) +
                    ((Limb)((S32)in2[3])) * ((S32)input[7]) +
                    ((Limb)((S32)in2[7])) * ((S32)input[3]) +
                    ((Limb)((S32)in2[1])) * ((S32)input[9]) +
                    ((Limb)((S32)in2[9])) * ((S32)input[1])) +
                ((Limb)((S32)in2[4])) * ((S32)input[6]) +
                ((Limb)((S32)in2[6])) * ((S32)input[4]) +
                ((Limb)((S32)in2[2])) * ((S32)input[8]) +
                ((Limb)((S32)in2[8])) * ((S32)input[2]);
            output[11] =
                ((Limb)((S32)in2[5])) * ((S32)input[6]) +
                ((Limb)((S32)in2[6])) * ((S32)input[5]) +
                ((Limb)((S32)in2[4])) * ((S32)input[7]) +
                ((Limb)((S32)in2[7])) * ((S32)input[4]) +
                ((Limb)((S32)in2[3])) * ((S32)input[8]) +
                ((Limb)((S32)in2[8])) * ((S32)input[3]) +
                ((Limb)((S32)in2[2])) * ((S32)input[9]) +
                ((Limb)((S32)in2[9])) * ((S32)input[2]);
            output[12] =
                ((Limb)((S32)in2[6])) * ((S32)input[6]) +
                2 * (((Limb)((S32)in2[5])) * ((S32)input[7]) +
                    ((Limb)((S32)in2[7])) * ((S32)input[5]) +
                    ((Limb)((S32)in2[3])) * ((S32)input[9]) +
                    ((Limb)((S32)in2[9])) * ((S32)input[3])) +
                ((Limb)((S32)in2[4])) * ((S32)input[8]) +
                ((Limb)((S32)in2[8])) * ((S32)input[4]);
            output[13] =
                ((Limb)((S32)in2[6])) * ((S32)input[7]) +
                ((Limb)((S32)in2[7])) * ((S32)input[6]) +
                ((Limb)((S32)in2[5])) * ((S32)input[8]) +
                ((Limb)((S32)in2[8])) * ((S32)input[5]) +
                ((Limb)((S32)in2[4])) * ((S32)input[9]) +
                ((Limb)((S32)in2[9])) * ((S32)input[4]);
            output[14] =
                2 *
                    (((Limb)((S32)in2[7])) * ((S32)input[7]) +
                    ((Limb)((S32)in2[5])) * ((S32)input[9]) +
                    ((Limb)((S32)in2[9])) * ((S32)input[5])) +
                ((Limb)((S32)in2[6])) * ((S32)input[8]) +
                ((Limb)((S32)in2[8])) * ((S32)input[6]);
            output[15] =
                ((Limb)((S32)in2[7])) * ((S32)input[8]) +
                ((Limb)((S32)in2[8])) * ((S32)input[7]) +
                ((Limb)((S32)in2[6])) * ((S32)input[9]) +
                ((Limb)((S32)in2[9])) * ((S32)input[6]);
            output[16] =
                ((Limb)((S32)in2[8])) * ((S32)input[8]) +
                2 * (((Limb)((S32)in2[7])) * ((S32)input[9]) +
                    ((Limb)((S32)in2[9])) * ((S32)input[7]));
            output[17] =
                ((Limb)((S32)in2[8])) * ((S32)input[9]) +
                ((Limb)((S32)in2[9])) * ((S32)input[8]);
            output[18] = 2 *
                ((Limb)((S32)in2[9])) * ((S32)input[9]);
        }

        /// <summary>
        /// Reduce a long form to a short form by taking the input mod 2^255 - 19.
        /// On entry: |output[i]| &lt; 14*2^54
        /// On exit: |output[0..8]| &lt; 280*2^54
        /// </summary>
        public static void freduce_degree(Limb[] output)
        {
            /* Each of these shifts and adds ends up multiplying the value by 19.
            *
            * For output[0..8], the absolute entry value is < 14*2^54 and we add, at
            * most, 19*14*2^54 thus, on exit, |output[0..8]| < 280*2^54. */
            output[8] += output[18] << 4;
            output[8] += output[18] << 1;
            output[8] += output[18];
            output[7] += output[17] << 4;
            output[7] += output[17] << 1;
            output[7] += output[17];
            output[6] += output[16] << 4;
            output[6] += output[16] << 1;
            output[6] += output[16];
            output[5] += output[15] << 4;
            output[5] += output[15] << 1;
            output[5] += output[15];
            output[4] += output[14] << 4;
            output[4] += output[14] << 1;
            output[4] += output[14];
            output[3] += output[13] << 4;
            output[3] += output[13] << 1;
            output[3] += output[13];
            output[2] += output[12] << 4;
            output[2] += output[12] << 1;
            output[2] += output[12];
            output[1] += output[11] << 4;
            output[1] += output[11] << 1;
            output[1] += output[11];
            output[0] += output[10] << 4;
            output[0] += output[10] << 1;
            output[0] += output[10];
        }

        public static Limb div_by_2_26(Limb v)
        {
            /* High word of v; no shift needed. */
            UInt32 highword = (UInt32)(((UInt64)v) >> 32);
            /* Set to all 1s if v was negative; else set to 0s. */
            S32 sign = ((S32)highword) >> 31;
            /* Set to 0x3ffffff if v was negative; else set to 0. */
            S32 roundoff = (S32)((UInt32)sign) >> 6;
            /* Should return v / (1<<26) */
            return (v + roundoff) >> 26;
        }

        /// <summary>
        /// return v / (2^25), using only shifts and adds.
        /// On entry: v can take any value.
        /// </summary>
        public static Limb div_by_2_25(Limb v)
        {
            /* High word of v; no shift needed*/
            UInt32 highword = (UInt32)(((UInt64)v) >> 32);
            /* Set to all 1s if v was negative; else set to 0s. */
            S32 sign = ((S32)highword) >> 31;
            /* Set to 0x1ffffff if v was negative; else set to 0. */
            S32 roundoff = (S32)((UInt32)sign) >> 7;
            /* Should return v / (1<<25) */
            return (v + roundoff) >> 25;
        }

        /// <summary>
        /// return v / (2^25), using only shifts and adds.
        /// On entry: v can take any value.
        /// </summary>
        public static S32 div_s32_by_2_25(S32 v)
        {
            S32 roundoff = (S32)((UInt32)(v >> 31)) >> 7;
            return (v + roundoff) >> 25;
        }

        /// <summary>
        /// Reduce all coefficients of the short form input so that |x| &lt; 2^26.
        /// On entry: |output[i]| &lt; 280*2^54
        /// </summary>
        public static void freduce_coefficients(Limb[] output)
        {
            output[10] = 0;

            for (int i = 0; i < 10; i += 2)
            {
                Limb over = div_by_2_26(output[i]);
                /* The entry condition (that |output[i]| < 280*2^54) means that over is, at
                * most, 280*2^28 in the first iteration of this loop. This is added to the
                * next limb and we can approximate the resulting bound of that limb by
                * 281*2^54. */
                output[i] -= over << 26;
                output[i + 1] += over;

                /* For the first iteration, |output[i+1]| < 281*2^54, thus |over| <
                * 281*2^29. When this is added to the next limb, the resulting bound can
                * be approximated as 281*2^54.
                *
                * For subsequent iterations of the loop, 281*2^54 remains a conservative
                * bound and no overflow occurs. */
                over = div_by_2_25(output[i + 1]);
                output[i + 1] -= over << 25;
                output[i + 2] += over;
            }
            /* Now |output[10]| < 281*2^29 and all other coefficients are reduced. */
            output[0] += output[10] << 4;
            output[0] += output[10] << 1;
            output[0] += output[10];

            output[10] = 0;

            /* Now output[1..9] are reduced, and |output[0]| < 2^26 + 19*281*2^29
            * So |over| will be no more than 2^16. */
            {
                Limb over = div_by_2_26(output[0]);
                output[0] -= over << 26;
                output[1] += over;
            }

            /* Now output[0,2..9] are reduced, and |output[1]| < 2^25 + 2^16 < 2^26. The
            * bound on |output[1]| is sufficient to meet our needs. */
        }

        /// <summary>
        /// A helpful wrapper around fproduct: output = in * in2.
        /// On entry: |in[i]| &lt; 2^27 and |in2[i]| &lt; 2^27.
        /// output must be distinct to both inputs. The output is reduced degree
        /// (indeed, one need only provide storage for 10 limbs) and |output[i]| &lt; 2^26.
        /// </summary>
        public static void fmul(Limb[] output, Limb[] input, Limb[] input2)
        {
            Limb[] t = new Limb[19];

            fproduct(t, input, input2);
            /* |t[i]| < 14*2^54 */
            freduce_degree(t);
            freduce_coefficients(t);
            /* |output[i]| < 2^26 */
            Array.Copy(t, 0, output, 0, 10);
        }

        /// <summary>
        /// Square a number: output = in**2
        /// output must be distinct from the input. The inputs are reduced coefficient
        /// form, the output is not. If you want to reduce the coeffecient too, call fsquare(...) instead.
        /// 
        /// output[x] &lt;= 14 * the largest product of the input limbs.
        /// </summary>
        public static void fsquare_inner(Limb[] output, Limb[] input)
        {
            output[0] = ((Limb)((S32)input[0])) * ((S32)input[0]);
            output[1] = 2 * ((Limb)((S32)input[0])) * ((S32)input[1]);
            output[2] = 2 * (((Limb)((S32)input[1])) * ((S32)input[1]) +
                              ((Limb)((S32)input[0])) * ((S32)input[2]));
            output[3] = 2 * (((Limb)((S32)input[1])) * ((S32)input[2]) +
                              ((Limb)((S32)input[0])) * ((S32)input[3]));
            output[4] = ((Limb)((S32)input[2])) * ((S32)input[2]) +
                         4 * ((Limb)((S32)input[1])) * ((S32)input[3]) +
                         2 * ((Limb)((S32)input[0])) * ((S32)input[4]);
            output[5] = 2 * (((Limb)((S32)input[2])) * ((S32)input[3]) +
                              ((Limb)((S32)input[1])) * ((S32)input[4]) +
                              ((Limb)((S32)input[0])) * ((S32)input[5]));
            output[6] = 2 * (((Limb)((S32)input[3])) * ((S32)input[3]) +
                              ((Limb)((S32)input[2])) * ((S32)input[4]) +
                              ((Limb)((S32)input[0])) * ((S32)input[6]) +
                         2 * ((Limb)((S32)input[1])) * ((S32)input[5]));
            output[7] = 2 * (((Limb)((S32)input[3])) * ((S32)input[4]) +
                              ((Limb)((S32)input[2])) * ((S32)input[5]) +
                              ((Limb)((S32)input[1])) * ((S32)input[6]) +
                              ((Limb)((S32)input[0])) * ((S32)input[7]));
            output[8] = ((Limb)((S32)input[4])) * ((S32)input[4]) +
                         2 * (((Limb)((S32)input[2])) * ((S32)input[6]) +
                              ((Limb)((S32)input[0])) * ((S32)input[8]) +
                         2 * (((Limb)((S32)input[1])) * ((S32)input[7]) +
                              ((Limb)((S32)input[3])) * ((S32)input[5])));
            output[9] = 2 * (((Limb)((S32)input[4])) * ((S32)input[5]) +
                              ((Limb)((S32)input[3])) * ((S32)input[6]) +
                              ((Limb)((S32)input[2])) * ((S32)input[7]) +
                              ((Limb)((S32)input[1])) * ((S32)input[8]) +
                              ((Limb)((S32)input[0])) * ((S32)input[9]));
            output[10] = 2 * (((Limb)((S32)input[5])) * ((S32)input[5]) +
                              ((Limb)((S32)input[4])) * ((S32)input[6]) +
                              ((Limb)((S32)input[2])) * ((S32)input[8]) +
                         2 * (((Limb)((S32)input[3])) * ((S32)input[7]) +
                              ((Limb)((S32)input[1])) * ((S32)input[9])));
            output[11] = 2 * (((Limb)((S32)input[5])) * ((S32)input[6]) +
                              ((Limb)((S32)input[4])) * ((S32)input[7]) +
                              ((Limb)((S32)input[3])) * ((S32)input[8]) +
                              ((Limb)((S32)input[2])) * ((S32)input[9]));
            output[12] = ((Limb)((S32)input[6])) * ((S32)input[6]) +
                         2 * (((Limb)((S32)input[4])) * ((S32)input[8]) +
                         2 * (((Limb)((S32)input[5])) * ((S32)input[7]) +
                              ((Limb)((S32)input[3])) * ((S32)input[9])));
            output[13] = 2 * (((Limb)((S32)input[6])) * ((S32)input[7]) +
                              ((Limb)((S32)input[5])) * ((S32)input[8]) +
                              ((Limb)((S32)input[4])) * ((S32)input[9]));
            output[14] = 2 * (((Limb)((S32)input[7])) * ((S32)input[7]) +
                              ((Limb)((S32)input[6])) * ((S32)input[8]) +
                         2 * ((Limb)((S32)input[5])) * ((S32)input[9]));
            output[15] = 2 * (((Limb)((S32)input[7])) * ((S32)input[8]) +
                              ((Limb)((S32)input[6])) * ((S32)input[9]));
            output[16] = ((Limb)((S32)input[8])) * ((S32)input[8]) +
                         4 * ((Limb)((S32)input[7])) * ((S32)input[9]);
            output[17] = 2 * ((Limb)((S32)input[8])) * ((S32)input[9]);
            output[18] = 2 * ((Limb)((S32)input[9])) * ((S32)input[9]);
        }

        /// <summary>
        /// fsquare sets output = in^2.
        /// On entry: The |in| argument is in reduced coefficients form and
        /// |in[i]| &lt; 2^27.
        /// 
        /// On exit: The |output| argument is in reduced coefficients form (indeed, oneneed only provide storage for 10 limbs) and |out[i]| &lt; 2^26.
        /// </summary>
        public static void fsquare(Limb[] output, Limb[] input)
        {
            Limb[] t = new Limb[19];
            fsquare_inner(t, input);
            /* |t[i]| < 14*2^54 because the largest product of two limbs will be <
             * 2^(27+27) and fsquare_inner adds together, at most, 14 of those
             * products. */
            freduce_degree(t);
            freduce_coefficients(t);
            /* |t[i]| < 2^26 */
            Array.Copy(t, 0, output, 0, 10);
        }

        /// <summary>
        /// Expand a 32-byte array into polynomial form.
        /// </summary>
        public static void fexpand(Limb[] output, byte[] input)
        {
            //TODO: Performance changes here.
            //This might be slow. It may be better to expand the function into 10 individual
            //lines of code so the compiler can optimize.
            Func<int, int, int, S32, object> _expand = (int n, int start, int shift, S32 mask) =>
            {
                output[n] = ((((Limb)input[start + 0]) |
                   ((Limb)input[start + 1]) << 8 |
                   ((Limb)input[start + 2]) << 16 |
                   ((Limb)input[start + 3]) << 24) >> shift) & mask;
                return null;
            };

            _expand.Invoke(0, 0, 0, 0x3ffffff);
            _expand.Invoke(1, 3, 2, 0x1ffffff);
            _expand.Invoke(2, 6, 3, 0x3ffffff);
            _expand.Invoke(3, 9, 5, 0x1ffffff);
            _expand.Invoke(4, 12, 6, 0x3ffffff);
            _expand.Invoke(5, 16, 0, 0x1ffffff);
            _expand.Invoke(6, 19, 1, 0x3ffffff);
            _expand.Invoke(7, 22, 3, 0x1ffffff);
            _expand.Invoke(8, 25, 4, 0x3ffffff);
            _expand.Invoke(9, 28, 6, 0x1ffffff);
        }

        /// <summary>
        /// s32_eq returns 0xffffffff iff a == b and zero otherwise.
        /// </summary>
        public static S32 s32_eq(S32 a, S32 b)
        {
            a = ~(a ^ b);
            a &= a << 16;
            a &= a << 8;
            a &= a << 4;
            a &= a << 2;
            a &= a << 1;
            return a >> 31;
        }

        /// <summary>
        /// s32_gte returns 0xffffffff if a >= b and zero otherwise, where a and b are
        /// both non-negative.
        /// </summary>
        /// <returns></returns>
        public static S32 s32_gte(S32 a, S32 b)
        {
            a -= b;
            /* a >= 0 iff a >= b. */
            return ~(a >> 31);
        }

        /// <summary>
        /// Take a fully reduced polynomial form number and contract it into a
        /// little-endian, 32-byte array.
        /// </summary>
        /// <param name="output">32-byte array, contracted form</param>
        /// <param name="input_limbs">Reduced degree/coeffecient Limb</param>
        /// <remarks>
        /// On entry: |input_limbs[i]| < 2^26
        /// </remarks>
        public static void fcontract(byte[] output, Limb[] input_limbs)
        {
            int i;
            int j;
            S32[] input = new S32[10];
            S32 mask;

            /* |input_limbs[i]| < 2^26, so it's valid to convert to an s32. */
            for (i = 0; i < 10; i++)
            {
                input[i] = (S32)input_limbs[i];
            }

            for (j = 0; j < 2; ++j)
            {
                for (i = 0; i < 9; ++i)
                {
                    if ((i & 1) == 1)
                    {
                        /* This calculation is a time-invariant way to make input[i]
                         * non-negative by borrowing from the next-larger limb. */
                        S32 mask2 = input[i] >> 31;
                        S32 carry = -((input[i] & mask2) >> 25);
                        input[i] = input[i] + (carry << 25);
                        input[i + 1] = input[i + 1] - carry;
                    }
                    else
                    {
                        S32 mask2 = input[i] >> 31;
                        S32 carry = -((input[i] & mask2) >> 26);
                        input[i] = input[i] + (carry << 26);
                        input[i + 1] = input[i + 1] - carry;
                    }
                }

                /* There's no greater limb for input[9] to borrow from, but we can multiply
                 * by 19 and borrow from input[0], which is valid mod 2^255-19. */
                {
                    S32 mask2 = input[9] >> 31;
                    S32 carry = -((input[9] & mask2) >> 25);
                    input[9] = input[9] + (carry << 25);
                    input[0] = input[0] - (carry * 19);
                }

                /* After the first iteration, input[1..9] are non-negative and fit within
                 * 25 or 26 bits, depending on position. However, input[0] may be
                 * negative. */
            }

            /* The first borrow-propagation pass above ended with every limb
               except (possibly) input[0] non-negative.

               If input[0] was negative after the first pass, then it was because of a
               carry from input[9]. On entry, input[9] < 2^26 so the carry was, at most,
               one, since (2**26-1) >> 25 = 1. Thus input[0] >= -19.

               In the second pass, each limb is decreased by at most one. Thus the second
               borrow-propagation pass could only have wrapped around to decrease
               input[0] again if the first pass left input[0] negative *and* input[1]
               through input[9] were all zero.  In that case, input[1] is now 2^25 - 1,
               and this last borrow-propagation step will leave input[1] non-negative. */
            {
                S32 mask2 = input[0] >> 31;
                S32 carry = -((input[0] & mask2) >> 26);
                input[0] = input[0] + (carry << 26);
                input[1] = input[1] - carry;
            }

            /* All input[i] are now non-negative. However, there might be values between
             * 2^25 and 2^26 in a limb which is, nominally, 25 bits wide. */
            for (j = 0; j < 2; j++)
            {
                for (i = 0; i < 9; i++)
                {
                    if ((i & 1) == 1)
                    {
                        S32 carry = input[i] >> 25;
                        input[i] &= 0x1ffffff;
                        input[i + 1] += carry;
                    }
                    else
                    {
                        S32 carry = input[i] >> 26;
                        input[i] &= 0x3ffffff;
                        input[i + 1] += carry;
                    }
                }

                {
                    S32 carry = input[9] >> 25;
                    input[9] &= 0x1ffffff;
                    input[0] += 19 * carry;
                }
            }

            /* If the first carry-chain pass, just above, ended up with a carry from
             * input[9], and that caused input[0] to be out-of-bounds, then input[0] was
             * < 2^26 + 2*19, because the carry was, at most, two.
             *
             * If the second pass carried from input[9] again then input[0] is < 2*19 and
             * the input[9] -> input[0] carry didn't push input[0] out of bounds. */

            /* It still remains the case that input might be between 2^255-19 and 2^255.
             * In this case, input[1..9] must take their maximum value and input[0] must
             * be >= (2^255-19) & 0x3ffffff, which is 0x3ffffed. */
            mask = s32_gte(input[0], 0x3ffffed);
            for (i = 1; i < 10; i++)
            {
                if ((i & 1) == 1)
                {
                    mask &= s32_eq(input[i], 0x1ffffff);
                }
                else
                {
                    mask &= s32_eq(input[i], 0x3ffffff);
                }
            }

            /* mask is either 0xffffffff (if input >= 2^255-19) and zero otherwise. Thus
             * this conditionally subtracts 2^255-19. */
            input[0] -= mask & 0x3ffffed;

            for (i = 1; i < 10; i++)
            {
                if ((i & 1) == 1)
                {
                    input[i] -= mask & 0x1ffffff;
                }
                else
                {
                    input[i] -= mask & 0x3ffffff;
                }
            }

            input[1] <<= 2;
            input[2] <<= 3;
            input[3] <<= 5;
            input[4] <<= 6;
            input[6] <<= 1;
            input[7] <<= 3;
            input[8] <<= 4;
            input[9] <<= 6;

            //TODO: Performance changes here.
            //This might be slow. It may be better to expand the function into 10 individual
            //lines of code so the compiler can optimize.
            Func<int, int, object> _contract = (int index, int s) =>
            {
                output[s + 0] |= (byte)(input[index] & 0xff);
                output[s + 1] = (byte)((input[index] >> 8) & 0xff);
                output[s + 2] = (byte)((input[index] >> 16) & 0xff);
                output[s + 3] = (byte)((input[index] >> 24) & 0xff);
                return null;
            };

            output[0] = 0;
            output[16] = 0;

            _contract.Invoke(0, 0);
            _contract.Invoke(1, 3);
            _contract.Invoke(2, 6);
            _contract.Invoke(3, 9);
            _contract.Invoke(4, 12);
            _contract.Invoke(5, 16);
            _contract.Invoke(6, 19);
            _contract.Invoke(7, 22);
            _contract.Invoke(8, 25);
            _contract.Invoke(9, 28);
        }

        /// <summary>
        /// Montgomery multiplication
        /// </summary>
        /// <param name="x2">x coordinate for 2Q</param>
        /// <param name="z2">z coordinate for 2Q</param>
        /// <param name="x3">x coordinate for Q + Q'</param>
        /// <param name="z3">z coordinate for Q + Q'</param>
        /// <param name="x">x coordinate of Q</param>
        /// <param name="z">z coordinate of Q</param>
        /// <param name="xprime">x coordinate of Q'</param>
        /// <param name="zprime">z coordinate of Q'</param>
        /// <param name="qmqp">Q - Q'</param>
        /// <remarks>
        /// Input: Q, Q', Q-Q'
        /// Output: 2Q, Q+Q'
        ///   x2 z2: long form
        ///   x3 z3: long form
        ///   x z: short form, destroyed
        ///   xprime zprime: short form, destroyed
        ///   qmqp: short form, preserved
        /// 
        /// On entry and exit, the absolute value of the limbs of all inputs and outputs
        /// are< 2^26.
        /// </remarks>
        public static void fmonty(Limb[] x2, Limb[] z2,
                           ref Limb[] x3, ref Limb[] z3,
                           Limb[] x, Limb[] z,
                           Limb[] xprime, Limb[] zprime,
                           Limb[] qmqp)
        {
            Limb[] origx, origxprime;
            Limb[] zzz, xx, zz, xxprime, zzprime, zzzprime, xxxprime;

            origx = (Limb[])x.Clone();

            fsum(x, z);
            /* |x[i]| < 2^27 */
            fdifference(z, origx);  /* does x - z */
                                    /* |z[i]| < 2^27 */
            origxprime = (Limb[])xprime.Clone();

            fsum(xprime, zprime);
            /* |xprime[i]| < 2^27 */
            fdifference(zprime, origxprime);
            /* |zprime[i]| < 2^27 */
            xxprime = new Limb[19];
            fproduct(xxprime, xprime, z);
            /* |xxprime[i]| < 14*2^54: the largest product of two limbs will be <
             * 2^(27+27) and fproduct adds together, at most, 14 of those products.
             * (Approximating that to 2^58 doesn't work out.) */
            zzprime = new Limb[19];
            fproduct(zzprime, x, zprime);
            /* |zzprime[i]| < 14*2^54 */
            freduce_degree(xxprime);
            freduce_coefficients(xxprime);
            /* |xxprime[i]| < 2^26 */
            freduce_degree(zzprime);
            freduce_coefficients(zzprime);
            /* |zzprime[i]| < 2^26 */
            origxprime = (Limb[])xxprime.Clone();
            fsum(xxprime, zzprime);
            /* |xxprime[i]| < 2^27 */
            fdifference(zzprime, origxprime);
            /* |zzprime[i]| < 2^27 */
            xxxprime = new Limb[19];
            fsquare(xxxprime, xxprime);
            /* |xxxprime[i]| < 2^26 */
            zzzprime = new Limb[19];
            fsquare(zzzprime, zzprime);
            /* |zzzprime[i]| < 2^26 */
            fproduct(zzprime, zzzprime, qmqp);
            /* |zzprime[i]| < 14*2^52 */
            freduce_degree(zzprime);
            freduce_coefficients(zzprime);
            /* |zzprime[i]| < 2^26 */
            x3 = (Limb[])xxxprime.Clone();
            z3 = (Limb[])zzprime.Clone();

            xx = new Limb[19];
            fsquare(xx, x);
            /* |xx[i]| < 2^26 */
            zz = new Limb[19];
            fsquare(zz, z);
            /* |zz[i]| < 2^26 */
            fproduct(x2, xx, zz);
            /* |x2[i]| < 14*2^52 */
            freduce_degree(x2);
            freduce_coefficients(x2);
            /* |x2[i]| < 2^26 */
            fdifference(zz, xx);  // does zz = xx - zz
                                  /* |zz[i]| < 2^27 */
            zzz = new Limb[19];
            fscalar_product(zzz, zz, 121665);
            /* |zzz[i]| < 2^(27+17) */
            /* No need to call freduce_degree here:
               fscalar_product doesn't increase the degree of its input. */
            freduce_coefficients(zzz);
            /* |zzz[i]| < 2^26 */
            fsum(zzz, xx);
            /* |zzz[i]| < 2^27 */
            fproduct(z2, zz, zzz);
            /* |z2[i]| < 14*2^(26+27) */
            freduce_degree(z2);
            freduce_coefficients(z2);
            /* |z2|i| < 2^26 */
        }

        /// <summary>
        /// Conditionally swap two reduced-form limb arrays if 'iswap' is 1, but leave
        /// them unchanged if 'iswap' is 0.  Runs in data-invariant time to avoid
        /// side-channel attacks.
        /// </summary>
        /// <remarks>
        /// This function requires that 'iswap' be 1 or 0; other values give
        /// wrong results.Also, the two limb arrays must be in reduced-coefficient,
        /// reduced-degree form: the values in a[10..19] or b[10..19] aren't swapped,
        /// and all all values in a[0..9], b[0..9] must have magnitude less than
        /// INT32_MAX.
        /// </remarks>
        public static void swap_conditional(Limb[] a, Limb[] b, long iswap)
        {
            int i;
            S32 swap = (S32)(-iswap);

            for (i = 0; i < 10; ++i)
            {
                S32 x = swap & (((S32)a[i]) ^ ((S32)b[i]));
                a[i] = ((S32)a[i]) ^ x;
                b[i] = ((S32)b[i]) ^ x;
            }
        }

        /// <summary>
        /// Calculates nQ where Q is the x-coordinate of a point on the curve
        /// </summary>
        /// <param name="resultx">the x coordinate of the resulting curve point (short form)</param>
        /// <param name="resultz">the z coordinate of the resulting curve point (short form)</param>
        /// <param name="n">a little endian, 32-byte number</param>
        /// <param name="q">a point of the curve (short form)</param>
        public static void cmult(Limb[] resultx, Limb[] resultz, byte[] n, Limb[] q)
        {
            Limb[] a = new Limb[19] { 0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
            Limb[] b = new Limb[19] { 1, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
            Limb[] c = new Limb[19] { 1, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
            Limb[] d = new Limb[19] { 0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
            Limb[] nqpqx = a;
            Limb[] nqpqz = b;
            Limb[] nqx = c;
            Limb[] nqz = d;
            Limb[] t = new Limb[19];

            Limb[] e = new Limb[19] { 0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
            Limb[] f = new Limb[19] { 1, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
            Limb[] g = new Limb[19] { 0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
            Limb[] h = new Limb[19] { 1, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };

            Limb[] nqpqx2 = e;
            Limb[] nqpqz2 = f;
            Limb[] nqx2 = g;
            Limb[] nqz2 = h;

            uint i, j;

            Array.Copy(q, 0, nqpqx, 0, 10);


            for (i = 0; i < 32; ++i)
            {
                byte mybyte = n[31 - i];
                for (j = 0; j < 8; ++j)
                {
                    Limb bit = mybyte >> 7;

                    swap_conditional(nqx, nqpqx, bit);
                    swap_conditional(nqz, nqpqz, bit);
                    fmonty(nqx2, nqz2,
                           ref nqpqx2, ref nqpqz2,
                           nqx, nqz,
                           nqpqx, nqpqz,
                           q);
                    swap_conditional(nqx2, nqpqx2, bit);
                    swap_conditional(nqz2, nqpqz2, bit);

                    t = nqx;
                    nqx = nqx2;
                    nqx2 = t;
                    t = nqz;
                    nqz = nqz2;
                    nqz2 = t;
                    t = nqpqx;
                    nqpqx = nqpqx2;
                    nqpqx2 = t;
                    t = nqpqz;
                    nqpqz = nqpqz2;
                    nqpqz2 = t;

                    mybyte <<= 1;
                }
            }
            Array.Copy(nqx, 0, resultx, 0, 10);

            Array.Copy(nqz, 0, resultz, 0, 10);
        }

        // -----------------------------------------------------------------------------
        // Ported from djb's code
        // -----------------------------------------------------------------------------
        public static void crecip(Limb[] output, Limb[] z)
        {
            Limb[] z2 = new Limb[19];
            Limb[] z9 = new Limb[19];
            Limb[] z11 = new Limb[19];
            Limb[] z2_5_0 = new Limb[19];
            Limb[] z2_10_0 = new Limb[19];
            Limb[] z2_20_0 = new Limb[19];
            Limb[] z2_50_0 = new Limb[19];
            Limb[] z2_100_0 = new Limb[19];
            Limb[] t0 = new Limb[19];
            Limb[] t1 = new Limb[19];
            int i;

            // z^2
            fsquare(z2, z);
            // 4
            fsquare(t1, z2);
            // 8
            fsquare(t0, t1);
            // 9
            fmul(z9, t0, z);
            // 11
            fmul(z11, z9, z2);
            // 22
            fsquare(t0, z11);
            // 2^5 - 2^0 = 31
            fmul(z2_5_0, t0, z9);

            // 2^6 - 2^1
            fsquare(t0, z2_5_0);
            // 2^7 - 2^2
            fsquare(t1, t0);
            // 2^8 - 2^3
            fsquare(t0, t1);
            // 2^9 - 2^4
            fsquare(t1, t0);
            // 2^10 - 2^5
            fsquare(t0, t1);
            // 2^10 - 2^0
            fmul(z2_10_0, t0, z2_5_0);

            // 2^11 - 2^1
            fsquare(t0, z2_10_0);
            // 2^12 - 2^2
            fsquare(t1, t0);

            // 2^20 - 2^10
            for (i = 2; i < 10; i += 2)
            {
                fsquare(t0, t1);
                fsquare(t1, t0);
            }
            // 2^20 - 2^0
            fmul(z2_20_0, t1, z2_10_0);

            // 2^21 - 2^1
            fsquare(t0, z2_20_0);
            // 2^22 - 2^2
            fsquare(t1, t0);
            // 2^40 - 2^20
            for (i = 2; i < 20; i += 2)
            {
                fsquare(t0, t1);
                fsquare(t1, t0);
            }
            // 2^40 - 2^0
            fmul(t0, t1, z2_20_0);

            // 2^41 - 2^1
            fsquare(t1, t0);
            // 2^42 - 2^2
            fsquare(t0, t1);
            // 2^50 - 2^10
            for (i = 2; i < 10; i += 2)
            {
                fsquare(t1, t0);
                fsquare(t0, t1);
            }
            // 2^50 - 2^0
            fmul(z2_50_0, t0, z2_10_0);

            // 2^51 - 2^1
            fsquare(t0, z2_50_0);
            // 2^52 - 2^2
            fsquare(t1, t0);
            // 2^100 - 2^50
            for (i = 2; i < 50; i += 2)
            {
                fsquare(t0, t1);
                fsquare(t1, t0);
            }
            // 2^100 - 2^0
            fmul(z2_100_0, t1, z2_50_0);

            // 2^101 - 2^1
            fsquare(t1, z2_100_0);
            // 2^102 - 2^2
            fsquare(t0, t1);
            // 2^200 - 2^100
            for (i = 2; i < 100; i += 2)
            {
                fsquare(t1, t0);
                fsquare(t0, t1);
            }
            // 2^200 - 2^0
            fmul(t1, t0, z2_100_0);

            // 2^201 - 2^1
            fsquare(t0, t1);
            // 2^202 - 2^2
            fsquare(t1, t0);
            // 2^250 - 2^50
            for (i = 2; i < 50; i += 2)
            {
                fsquare(t0, t1);
                fsquare(t1, t0);
            }
            // 2^250 - 2^0
            fmul(t0, t1, z2_50_0);

            // 2^251 - 2^1
            fsquare(t1, t0);
            // 2^252 - 2^2
            fsquare(t0, t1);
            // 2^253 - 2^3
            fsquare(t1, t0);
            // 2^254 - 2^4
            fsquare(t0, t1);
            // 2^255 - 2^5
            fsquare(t1, t0);

            // 2^255 - 21
            fmul(output, t1, z11);
        }

        public static int curve25519_donna(byte[] mypublic, byte[] secret, byte[] basepoint)
        {
            Limb[] bp = new Limb[19];
            Limb[] x = new Limb[19];
            Limb[] z = new Limb[19];
            Limb[] zmone = new Limb[19];
            byte[] e = new byte[32];
            int i;

            for (i = 0; i < 32; ++i)
            {
                e[i] = secret[i];
            }

            fexpand(bp, basepoint);
            cmult(x, z, e, bp);
            crecip(zmone, z);
            fmul(z, x, zmone);
            fcontract(mypublic, z);
            return 0;
        }
    }
}
