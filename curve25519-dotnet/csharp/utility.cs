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

using System.Diagnostics;

namespace org.whispersystems.curve25519.csharp
{
    public class utility
    {
        public static void print_vector(string name, byte[] v)
        {
            int count;
            Debug.WriteLine($"{name} = ");
            for (count = 0; count < 32; count++)
            {
                Debug.WriteLine("{0:X2}", v[count]);
            }
            Debug.WriteLine("");
        }

        public static void print_bytes(string name, byte[] v, int numbytes)
        {
            int count;
            Debug.WriteLine($"{name} = ");
            for (count = 0; count < numbytes; count++)
            {
                Debug.WriteLine("{0:X2}", v[count]);
            }
            Debug.WriteLine("");
        }

        public static void print_fe(string name, int[] iIn)
        {
            byte[] bytes = new byte[32];
            Fe_tobytes.fe_tobytes(bytes, iIn);
            print_vector(name, bytes);
        }
    }
}
