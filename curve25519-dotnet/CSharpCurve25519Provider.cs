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
    /// Default PCL-compatible implementation of Curve25519
    /// </summary>
    public class CSharpCurve25519Provider : BaseCSharpCurve25519Provider
    {
        //Note: For now, I'm sticking with the Bouncy Castle SHA 512 implementation,
        //because it is pure C#. The PCLCrypto random provider is probably the only part
        //of this entire implementation that depends on something non-C# (see the
        //PCLCrypto wiki for an explanation). And there, it is better to trust the
        //operating system's random number generator, unless someone wants to contribute
        //a pure C# way to reliably produce random numbers. Such an implementation
        //would have to go through a lot of scrutiny before being used here.

        public CSharpCurve25519Provider() :
            base(new BouncyCastleDotNETSha512Provider(), new PCLSecureRandomProvider())
        {
        }

        public CSharpCurve25519Provider(ISha512 sha, SecureRandomProvider random)
            : base(sha, random)
        {
        }

        public override bool isNative()
        {
            return false;
        }
    }
}
