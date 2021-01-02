using Evo.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Evo.Statics
{
    class Root
    {
        public static Keccak256Service Keccak256 { get; set; } = new Keccak256Service();
    }
}
