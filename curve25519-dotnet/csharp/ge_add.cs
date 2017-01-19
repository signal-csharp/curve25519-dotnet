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

    public class Ge_add
    {

        //CONVERT #include "ge.h"

        /*
        r = p + q
        */

        public static void ge_add(Ge_p1p1 r, Ge_p3 p, Ge_cached q)
        {
            int[] t0 = new int[10];
            //CONVERT #include "ge_add.h"

            /* qhasm: enter ge_add */

            /* qhasm: fe X1 */

            /* qhasm: fe Y1 */

            /* qhasm: fe Z1 */

            /* qhasm: fe Z2 */

            /* qhasm: fe T1 */

            /* qhasm: fe ZZ */

            /* qhasm: fe YpX2 */

            /* qhasm: fe YmX2 */

            /* qhasm: fe T2d2 */

            /* qhasm: fe X3 */

            /* qhasm: fe Y3 */

            /* qhasm: fe Z3 */

            /* qhasm: fe T3 */

            /* qhasm: fe YpX1 */

            /* qhasm: fe YmX1 */

            /* qhasm: fe A */

            /* qhasm: fe B */

            /* qhasm: fe C */

            /* qhasm: fe D */

            /* qhasm: YpX1 = Y1+X1 */
            /* asm 1: Fe_add.fe_add(>YpX1=fe#1,<Y1=fe#12,<X1=fe#11); */
            /* asm 2: Fe_add.fe_add(>YpX1=r.X,<Y1=p.Y,<X1=p.X); */
            Fe_add.fe_add(r.X, p.Y, p.X);

            /* qhasm: YmX1 = Y1-X1 */
            /* asm 1: Fe_sub.fe_sub(>YmX1=fe#2,<Y1=fe#12,<X1=fe#11); */
            /* asm 2: Fe_sub.fe_sub(>YmX1=r.Y,<Y1=p.Y,<X1=p.X); */
            Fe_sub.fe_sub(r.Y, p.Y, p.X);

            /* qhasm: A = YpX1*YpX2 */
            /* asm 1: Fe_mul.fe_mul(>A=fe#3,<YpX1=fe#1,<YpX2=fe#15); */
            /* asm 2: Fe_mul.fe_mul(>A=r.Z,<YpX1=r.X,<YpX2=q.YplusX); */
            Fe_mul.fe_mul(r.Z, r.X, q.YplusX);

            /* qhasm: B = YmX1*YmX2 */
            /* asm 1: Fe_mul.fe_mul(>B=fe#2,<YmX1=fe#2,<YmX2=fe#16); */
            /* asm 2: Fe_mul.fe_mul(>B=r.Y,<YmX1=r.Y,<YmX2=q.YminusX); */
            Fe_mul.fe_mul(r.Y, r.Y, q.YminusX);

            /* qhasm: C = T2d2*T1 */
            /* asm 1: Fe_mul.fe_mul(>C=fe#4,<T2d2=fe#18,<T1=fe#14); */
            /* asm 2: Fe_mul.fe_mul(>C=r.T,<T2d2=q.T2d,<T1=p.T); */
            Fe_mul.fe_mul(r.T, q.T2d, p.T);

            /* qhasm: ZZ = Z1*Z2 */
            /* asm 1: Fe_mul.fe_mul(>ZZ=fe#1,<Z1=fe#13,<Z2=fe#17); */
            /* asm 2: Fe_mul.fe_mul(>ZZ=r.X,<Z1=p.Z,<Z2=q.Z); */
            Fe_mul.fe_mul(r.X, p.Z, q.Z);

            /* qhasm: D = 2*ZZ */
            /* asm 1: Fe_add.fe_add(>D=fe#5,<ZZ=fe#1,<ZZ=fe#1); */
            /* asm 2: Fe_add.fe_add(>D=t0,<ZZ=r.X,<ZZ=r.X); */
            Fe_add.fe_add(t0, r.X, r.X);

            /* qhasm: X3 = A-B */
            /* asm 1: Fe_sub.fe_sub(>X3=fe#1,<A=fe#3,<B=fe#2); */
            /* asm 2: Fe_sub.fe_sub(>X3=r.X,<A=r.Z,<B=r.Y); */
            Fe_sub.fe_sub(r.X, r.Z, r.Y);

            /* qhasm: Y3 = A+B */
            /* asm 1: Fe_add.fe_add(>Y3=fe#2,<A=fe#3,<B=fe#2); */
            /* asm 2: Fe_add.fe_add(>Y3=r.Y,<A=r.Z,<B=r.Y); */
            Fe_add.fe_add(r.Y, r.Z, r.Y);

            /* qhasm: Z3 = D+C */
            /* asm 1: Fe_add.fe_add(>Z3=fe#3,<D=fe#5,<C=fe#4); */
            /* asm 2: Fe_add.fe_add(>Z3=r.Z,<D=t0,<C=r.T); */
            Fe_add.fe_add(r.Z, t0, r.T);

            /* qhasm: T3 = D-C */
            /* asm 1: Fe_sub.fe_sub(>T3=fe#4,<D=fe#5,<C=fe#4); */
            /* asm 2: Fe_sub.fe_sub(>T3=r.T,<D=t0,<C=r.T); */
            Fe_sub.fe_sub(r.T, t0, r.T);

            /* qhasm: return */
        }


    }
}
