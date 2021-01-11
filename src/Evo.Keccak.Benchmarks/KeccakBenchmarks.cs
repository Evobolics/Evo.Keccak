using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using Evo.Services.Cryptography.Keccak;
using Evo.Statics;
using System;
using System.Security.Cryptography;
using System.Linq;

namespace Evo.Keccak.Benchmarks
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var summary = BenchmarkRunner.Run<KeccakBenchmarks>(Configure());
        }

        public static IConfig Configure()
        {
            
            var config = DefaultConfig.Instance;

            config = config.WithOptions(ConfigOptions.DisableOptimizationsValidator);

            return config;
            
        }
    }

    [SimpleJob(RuntimeMoniker.NetCoreApp50)]
    [RPlotExporter]
    public class KeccakBenchmarks
    {
        [Params("The quick brown fox jumps over the lazy dog")]
        public string input;

        private Keccak1600Service_Teaching2 _Teaching;

        [GlobalSetup]
        public void Setup()
        {
            _Teaching = new Keccak1600Service_Teaching2();
       
        }

        [Benchmark]
        public string Teaching_1() => _Teaching.FromString(input).ToHexString(hexPrefix: false);

        [Benchmark]
        public string Teaching_2() => _Teaching.FromString(input).ToHexString(hexPrefix: false);

        [Benchmark(Baseline =true)]
        public string Optimized() => KeccakRoot.Keccak256.FromString(input).ToHexString(hexPrefix: false);
    }
}
