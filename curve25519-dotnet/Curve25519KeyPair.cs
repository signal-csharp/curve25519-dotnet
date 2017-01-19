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

namespace org.whispersystems.curve25519
{


    /// <summary>
    /// A tuple that contains a Curve25519 public and private key.
    /// </summary>
    public class Curve25519KeyPair
    {

        private readonly byte[] publicKey;
        private readonly byte[] privateKey;

        public Curve25519KeyPair(byte[] publicKey, byte[] privateKey)
        {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns>The Curve25519 public key.</returns>
        public byte[] getPublicKey()
        {
            return publicKey;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns>The Curve25519 private key.</returns>
        public byte[] getPrivateKey()
        {
            return privateKey;
        }
    }
}
