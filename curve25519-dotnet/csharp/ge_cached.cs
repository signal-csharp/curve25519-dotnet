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


namespace org.whispersystems.curve25519.csharp
{

    public class Ge_cached
    {

        public int[] YplusX;
        public int[] YminusX;
        public int[] Z;
        public int[] T2d;

        public Ge_cached()
        {
            YplusX = new int[10];
            YminusX = new int[10];
            Z = new int[10];
            T2d = new int[10];
        }
    }

}
