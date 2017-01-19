using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace System
{
    /// <summary>
    /// System.ICloneable workaround in PCL libraries.
    /// </summary>
    public interface IPclCloneable
    {
        IPclCloneable Clone();
    }
}
