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

using System;

namespace org.whispersystems.curve25519.csharp
{
    public class Sc_cmov
    {
        public static void sc_cmov(Span<byte> f, ReadOnlySpan<byte> g, byte b)
        {
            int count = 32;
            byte[] x = new byte[32];
            for (count = 0; count < 32; count++)
            {
                x[count] = (byte)(f[count] ^ g[count]);
            }
            b = (byte)-b;
            for (count = 0; count < 32; count++)
            {
                x[count] &= b;
            }
            for (count = 0; count < 32; count++)
            {
                f[count] = (byte)(f[count] ^ x[count]);
            }
        }
    }
}
