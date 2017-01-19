/** 
 * Copyright (C) 2017 langboost, golf1052
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

using org.whispersystems.curve25519.csharp;

namespace org.whispersystems.curve25519
{
    /// <summary>
    /// Base class for all implementations of providers Curve25519.
    /// </summary>
    public abstract class Curve25519Provider
    {
        public const int PRIVATE_KEY_LEN = 32;

        public abstract byte[] calculateAgreement(byte[] ourPrivate, byte[] theirPublic);
        public abstract byte[] calculateSignature(byte[] random, byte[] privateKey, byte[] message);
        public abstract byte[] generatePrivateKey();
        public abstract byte[] generatePrivateKey(byte[] random);
        public abstract byte[] generatePublicKey(byte[] privateKey);
        public abstract byte[] getRandom(int length);
        public abstract bool isNative();
        public abstract void setRandomProvider(SecureRandomProvider provider);
        public abstract void setSha512Provider(ISha512 provider);
        public abstract bool verifySignature(byte[] publicKey, byte[] message, byte[] signature);
        public abstract byte[] calculateVrfSignature(byte[] random, byte[] privateKey, byte[] message);
        public abstract byte[] verifyVrfSignature(byte[] publicKey, byte[] message, byte[] signature);
    }
}
