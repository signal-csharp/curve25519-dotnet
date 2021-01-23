/** 
 * Copyright (C) 2016 langboost, golf1052
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

namespace org.whispersystems.curve25519.csharp
{

    public class Arrays
    {
        /// <summary>
        /// Assigns the specified byte value to each element of the specified span
        /// of bytes.
        /// </summary>
        /// <param name="a">the array to be filled</param>
        /// <param name="val">the value to be stored in all elements of the span</param>
        public static void Fill(Span<byte> a, byte val)
        {
            Fill(a, val, (uint)a.Length);
        }

        public static void Fill(Span<byte> a, byte val, uint length)
        {
            for (int i = 0; i < length; i++)
                a[i] = val;
        }

        /// <summary>
        /// This is a timing attack resistant implementation of MessageDigest.isEqual(). According to
        /// https://codahale.com/a-lesson-in-timing-attacks/ , this helper method in the Java
        /// environment is vulnerable to timing attacks.
        /// </summary>
        public static bool isEqual(byte[] first, byte[] second)
        {
            if (first.Length != second.Length)
            {
                return false;
            }

            int result = 0;
            for (int i = 0; i < first.Length; i++)
            {
                result |= first[i] ^ second[i];
            }
            return result == 0;
        }

        public static bool isEqual(byte[] first, byte[] second, int length)
        {
            int result = 0;
            for (int i = 0; i < length; i++)
            {
                result |= first[i] ^ second[i];
            }
            return result == 0;
        }
    }
}
