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
    public class Fe_mont_rhs
    {
        public static void fe_mont_rhs(int[] v2, int[] u)
        {
            int[] A = new int[10];
            int[] one = new int[10];
            int[] u2 = new int[10];
            int[] Au = new int[10];
            int[] inner = new int[10];

            Fe_1.fe_1(one);
            Fe_0.fe_0(A);
            A[0] = 486662;                      /* A = 486662 */

            Fe_sq.fe_sq(u2, u);                 /* u^2 */
            Fe_mul.fe_mul(Au, A, u);            /* Au */
            Fe_add.fe_add(inner, u2, Au);       /* u^2 + Au */
            Fe_add.fe_add(inner, inner, one);   /* u^2 + Au + 1 */
            Fe_mul.fe_mul(v2, u, inner);        /* u(u^2 + Au + 1) */
        }
    }
}
