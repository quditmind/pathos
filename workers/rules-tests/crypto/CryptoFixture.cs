// Test fixture for workers/rules/pathos-crypto.yml (C#). Not compiled.
using System;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

public class CryptoFixture
{
    public void Hashing(byte[] data)
    {
        // ruleid: pathos.crypto.csharp.weak-hash
        var a = MD5.Create();
        // ruleid: pathos.crypto.csharp.weak-hash
        var b = new SHA1Managed();
        // ok: pathos.crypto.csharp.weak-hash
        var c = SHA256.Create();
    }

    public void Ciphers(byte[] key)
    {
        // ruleid: pathos.crypto.csharp.weak-cipher
        var d = TripleDES.Create();
        // ok: pathos.crypto.csharp.weak-cipher
        var aes = Aes.Create();
        // ruleid: pathos.crypto.csharp.ecb-mode
        aes.Mode = CipherMode.ECB;
        // ok: pathos.crypto.csharp.ecb-mode
        aes.Mode = CipherMode.CBC;
        // ruleid: pathos.crypto.csharp.static-iv
        aes.IV = Encoding.UTF8.GetBytes("0000000000000000");
        // ruleid: pathos.crypto.csharp.static-iv
        aes.IV = new byte[16];
        // ok: pathos.crypto.csharp.static-iv
        aes.GenerateIV();
    }

    public void Keys()
    {
        // ruleid: pathos.crypto.csharp.small-rsa-key
        var r1 = new RSACryptoServiceProvider(1024);
        // ruleid: pathos.crypto.csharp.small-rsa-key
        var r2 = RSA.Create(512);
        // ok: pathos.crypto.csharp.small-rsa-key
        var r3 = RSA.Create(3072);
    }

    public string Tokens()
    {
        // ruleid: pathos.crypto.csharp.insecure-random-secret
        string resetToken = new Random().Next().ToString("x");
        // ok: pathos.crypto.csharp.insecure-random-secret
        string csrfToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        // ok: pathos.crypto.csharp.insecure-random-secret
        int delay = new Random().Next(100);
        return resetToken + csrfToken + delay;
    }

    public void Tls()
    {
        var handler = new HttpClientHandler();
        // ruleid: pathos.crypto.csharp.tls-verification-disabled
        handler.ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true;
        // ruleid: pathos.crypto.csharp.tls-verification-disabled
        ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) => true;
        // ruleid: pathos.crypto.csharp.tls-verification-disabled
        handler.SslProtocols = SslProtocols.Tls11;
        // ok: pathos.crypto.csharp.tls-verification-disabled
        handler.SslProtocols = SslProtocols.Tls13;
    }

    public void Hardcoded()
    {
        var aes = Aes.Create();
        // ruleid: pathos.crypto.csharp.hardcoded-key
        aes.Key = Encoding.UTF8.GetBytes("0123456789abcdef0123456789abcdef");
        // ruleid: pathos.crypto.csharp.hardcoded-key
        var signing = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("fixture-signing-key-not-real-0001"));
        // ok: pathos.crypto.csharp.hardcoded-key
        aes.Key = Convert.FromBase64String(Environment.GetEnvironmentVariable("AES_KEY"));
    }
}
