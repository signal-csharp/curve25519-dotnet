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

namespace org.whispersystems.curve25519.csharp
{
    public class Crypto_verify_32
    {
        public static int crypto_verify_32(byte[] x, byte[] y)
        {
            return crypto_verify_32(x, y, 32);
        }

        public static int crypto_verify_32(byte[] x, byte[] y, int length)
        {
            int differentbits = 0;
            for (int count = 0; count < length; count++)
            {
                differentbits |= (x[count] ^ y[count]);
            }
            return (1 & ((differentbits - 1) >> 8)) - 1;
        }

        public static int crypto_verify_32(int[] x, int[] y)
        {
            int differentbits = 0;
            for (int count = 0; count < 10; count++)
            {
                differentbits |= (x[count] ^ y[count]);
            }
            return (1 & ((differentbits - 1) >> 8)) - 1;
        }
    }
}
