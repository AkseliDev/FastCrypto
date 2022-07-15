# FastCrypto

Library of crypto algorithms that are optimized to the last bit for .NET.

The goal is to nitpick every single bit of performance out of the algorithms specifically for C#.

## Current Algorithms
 - RC4
 
 ## Benchmark comparison
 
 ### RC4 (FastCrypto) vs RC4 (BouncyCastle)
  - 3 times faster!
  
  |           Method |     Mean |     Error |    StdDev |
  |----------------- |---------:|----------:|----------:|
  | FastCrypto_RC4   | 1.494 us | 0.0017 us | 0.0013 us |
  | BouncyCastle_RC4 | 4.472 us | 0.0045 us | 0.0042 us |
