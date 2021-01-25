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

using Org.BouncyCastle.Crypto.Digests;

namespace org.whispersystems.curve25519
{
    public class BouncyCastleDotNETSha512Provider : org.whispersystems.curve25519.csharp.ISha512
    {
        public void calculateDigest(byte[] digestOut, byte[] inData, long length)
        {
            // Not converting this to use Span<byte> because we would need to do 2 array copies
            // byte[] digestOutArray = digestOut.ToArray() (copy 1)
            // d.DoFinal(digestOutArray, 0); (yes this is a copy into digestOutArray but that happens in either implementation)
            // digestOutArray.CopyTo(digestOut); (copy 2)

            Sha512Digest d = new Sha512Digest();
            d.BlockUpdate(inData, 0, (int)length);
            d.DoFinal(digestOut, 0);
        }
    }
}
