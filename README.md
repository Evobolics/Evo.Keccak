# Evo.Keccak
An implementation of the Keccak-f[1600] algorithm.

The [package](https://www.nuget.org/packages/Evo.Keccak/) is located on [nuget.org](https://www.nuget.org/).

This code was originally forked from the [Meadow](https://github.com/MeadowSuite/Meadow/) under the MIT license.  
# Usage

Install [ Package Evo.Keccak](https://www.nuget.org/packages/Evo.Keccak/)

```csharp

using System;

// Example 1
string input = "Gig'em";

var result = input.HashToKeccak256().ToHexString(hexPrefix: false);

// Example 2

var bytes = input.GetUtf8Bytes();

var result = bytes.HashToKeccak256Bytes();

```


# Notes

Books on Keccak and SHA-3
* http://www.crypto-textbook.com/  (includes free download of the Keccak Chapter 11b)
  * [Amazon Link](https://www.amazon.com/gp/product/3642041000) 

Papers on Keccak and SHA-3 (note, they are slightly different)
* https://keccak.team/index.html
* https://keccak.team/files/CSF-0.1.pdf
* https://keccak.team/files/Keccak-reference-3.0.pdf
* https://www.iacr.org/archive/eurocrypt2013/78810311/78810311.pdf
* https://keccak.team/files/Keccak-submission-3.pdf (Explains Why Keccak-f[1600] was choosen)
* https://keccak.team/files/Keccak-implementation-3.2.pdf
* https://keccak.team/files/CSF-0.1.pdf

Articles on Keccak and SHA-3
* https://en.wikipedia.org/wiki/SHA-3
* https://medium.com/bugbountywriteup/breaking-down-sha-3-algorithm-70fe25e125b6
* https://medium.com/asecuritysite-when-bob-met-alice/one-of-the-greatest-advancements-in-cybersecurity-the-sponge-function-keccak-and-shake-6e6c8e298682
* https://crypto.stackexchange.com/questions/26747/why-have-round-constants-in-hashes
* https://keccak.team/keccak_specs_summary.html


Videos on Keccak and SHA-3
* https://www.youtube.com/watch?v=JWskjzgiIa4

List of Keccek Implementations in various Languages 
* https://keccak.team/software.html
* https://github.com/XKCP/XKCP

# Implementation Benchmarks

```
|     Method |                input |     Mean |     Error |    StdDev | Ratio | RatioSD |
|----------- |--------------------- |---------:|----------:|----------:|------:|--------:|
| Teaching_1 | The q(...)y dog [43] | 2.846 us | 0.0549 us | 0.0588 us |  1.48 |    0.04 |
| Teaching_2 | The q(...)y dog [43] | 2.825 us | 0.0561 us | 0.0525 us |  1.47 |    0.04 |
|  Optimized | The q(...)y dog [43] | 1.925 us | 0.0326 us | 0.0289 us |  1.00 |    0.00 |

```