

using curve25519.donna;
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
using org.whispersystems.curve25519.csharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace curve25519
{
    /// <summary>
    /// Uses the "Donna" implementation for private/public key manipulation and agreement,
    /// but retains the Ed25519 implementation from its base class for signatures and verification.
    /// </summary>
    public class DonnaCSharpCurve25519Provider : BaseCSharpCurve25519Provider
    {
        public DonnaCSharpCurve25519Provider(ISha512 sha512provider, SecureRandomProvider secureRandomProvider)
            : base(sha512provider, secureRandomProvider) { }

        private byte[] basepoint = new byte[] {
            9, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0 };

        public override byte[] generatePublicKey(byte[] privateKey)
        {
            byte[] publicKey = new byte[32];
            Curve25519Donna.curve25519_donna(publicKey, privateKey, basepoint);
            return publicKey;
        }

        public override byte[] calculateAgreement(byte[] ourPrivate, byte[] theirPublic)
        {
            byte[] sharedKeyAgreement = new byte[32];
            Curve25519Donna.curve25519_donna(sharedKeyAgreement, ourPrivate, theirPublic);
            return sharedKeyAgreement;
        }

        public override bool isNative()
        {
            return false;
        }
    }
}
