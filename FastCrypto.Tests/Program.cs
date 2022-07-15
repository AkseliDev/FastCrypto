
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using FastCrypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System.Text;

BenchmarkRunner.Run<CryptoTest>();
Console.ReadKey();

public class CryptoTest {

    static byte[] EncryptionKey = { 200, 100, 18, 164, 146, 232, 122, 183, 58, 214, 130, 177, 50 };

    // FastCrypto rc4 implementation
    RC4 _fastRC4;

    // BouncyCastle rc4 implementation
    RC4Engine _bouncyRC4;

    // seperate blocks with the same data (obviously)
    byte[] _bytes1;
    byte[] _bytes2;

    public CryptoTest() {

        // init fast rc4
        _fastRC4 = new RC4(EncryptionKey);

        // init bouncy rc4
        _bouncyRC4 = new RC4Engine();
        _bouncyRC4.Init(true, new KeyParameter(EncryptionKey));

        _bytes1 = new byte[1024];
        _bytes2 = new byte[1024];
    }

    
    [Benchmark]
    public void FastCrypto_RC4() {
        _fastRC4.ProcessBytes(_bytes1, 0, _bytes1.Length);
    }

    [Benchmark]
    public void BouncyCastle_RC4() {
        _bouncyRC4.ProcessBytes(_bytes2, 0, _bytes2.Length, _bytes2, 0);
    }
}