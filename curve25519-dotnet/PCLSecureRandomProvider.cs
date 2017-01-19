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

using org.whispersystems.curve25519;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace curve25519
{
    /// <summary>
    /// Exposes the PCLCrypto library as a source of secure random information.
    /// See https://github.com/AArnott/PCLCrypto for details.
    /// </summary>
    public class PCLSecureRandomProvider : SecureRandomProvider
    {
        public void nextBytes(byte[] output)
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(output);
            }
        }

        public int nextInt(int maxValue)
        {
            byte[] rnd = new byte[sizeof(int)];
            return BitConverter.ToInt32(rnd, 0) % maxValue;
        }
    }
}
