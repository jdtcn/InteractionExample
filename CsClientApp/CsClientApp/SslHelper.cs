using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace CsClientApp
{
    public static class SslHelper
    {
        private const int KEY_STRENGTH = 2048;
        private const string ALGORITHM = "SHA256WITHRSA";
        private const string AppId = "{d44dd183-66da-40da-9cc3-1663a3186039}";

        public static X509Certificate2 CheckOrCreateCertificates(string certName, string rootName)
        {
            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            var existingCert = store.Certificates.Find(X509FindType.FindBySubjectName, certName, false);
            if (existingCert.Count > 0)
            {
                store.Close();
                return existingCert[0];
            }
            else
            {
                return CreateCertificate(certName, rootName);
            }
        }

        private static void RegisterSslOnPort(string certThumbprint)
        {
            var commands = new string[]
            {
                $"http delete sslcert ipport=0.0.0.0:{Program.HTTPSPORT}",
                $"http add sslcert ipport=0.0.0.0:{Program.HTTPSPORT} certhash={certThumbprint} appid=\"{AppId}\""
            };
            foreach (var cmd in commands)
            {
                var procStartInfo = new ProcessStartInfo("netsh", cmd)
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                var process = Process.Start(procStartInfo);
                while (!process.StandardOutput.EndOfStream)
                {
                    string line = process.StandardOutput.ReadLine();
                    Console.WriteLine(line);
                }
                process.WaitForExit();
            }
        }

        private static X509Certificate2 CreateCertificate(string certName, string rootName)
        {
            if (Program.IsElevated)
            {
                var rootStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
                rootStore.Open(OpenFlags.ReadWrite);
                var personalStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                personalStore.Open(OpenFlags.ReadWrite);

                var caCert = GenerateCACertificate(rootName);
                var cert = GenerateSSLCertificate(certName, caCert);
                rootStore.Add(caCert);
                personalStore.Add(cert);

                rootStore.Close();
                personalStore.Close();

                RegisterSslOnPort(cert.Thumbprint);

                return cert;
            }
            else
            {
                RunElevated();
                return null;
            }
        }

        private static X509Certificate2 GenerateCACertificate(string rootName, X509Certificate2 issuer = null)
        {
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            var certificateGenerator = new X509V3CertificateGenerator();

            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            certificateGenerator.SetIssuerDN(new X509Name($"CN={rootName}"));
            certificateGenerator.SetSubjectDN(new X509Name($"CN={rootName}"));

            if (issuer != null)
            {
                var authorityKeyIdentifier = new AuthorityKeyIdentifierStructure(
                    DotNetUtilities.FromX509Certificate(issuer));
                certificateGenerator.AddExtension(
                    X509Extensions.AuthorityKeyIdentifier.Id, false, authorityKeyIdentifier);
            }

            certificateGenerator.AddExtension(
                X509Extensions.BasicConstraints.Id, true, new BasicConstraints(true));

            certificateGenerator.SetNotBefore(DateTime.UtcNow.Date.AddHours(-12));
            certificateGenerator.SetNotAfter(DateTime.UtcNow.Date.AddYears(100));

            var keyGenerationParameters = new KeyGenerationParameters(random, KEY_STRENGTH);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);

            var subjectKeyPair = keyPairGenerator.GenerateKeyPair();
            var issuerKeyPair = issuer == null
                ? subjectKeyPair
                : DotNetUtilities.GetKeyPair(issuer.PrivateKey);

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            var signatureFactory = new Asn1SignatureFactory(ALGORITHM, issuerKeyPair.Private, random);
            var certificate = certificateGenerator.Generate(signatureFactory);

            return new X509Certificate2(certificate.GetEncoded())
            {
                PrivateKey = ToDotNetKey((RsaPrivateCrtKeyParameters)subjectKeyPair.Private)
            };
        }

        private static X509Certificate2 GenerateSSLCertificate(string subjectName, X509Certificate2 issuer)
        {
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            var keyPairGenerator = new RsaKeyPairGenerator();

            keyPairGenerator.Init(new KeyGenerationParameters(random, KEY_STRENGTH));

            var keyPair = keyPairGenerator.GenerateKeyPair();

            var certificateGenerator = new X509V3CertificateGenerator();

            var certName = new X509Name($"CN={subjectName}");
            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), random);

            certificateGenerator.SetSerialNumber(serialNumber);
            certificateGenerator.SetSubjectDN(certName);
            certificateGenerator.SetIssuerDN(certName);
            certificateGenerator.SetNotAfter(DateTime.Now.AddYears(100));
            certificateGenerator.SetNotBefore(DateTime.Now.Subtract(new TimeSpan(7, 0, 0, 0)));
            certificateGenerator.SetPublicKey(keyPair.Public);

            var authorityKeyIdentifier = new AuthorityKeyIdentifierStructure(DotNetUtilities.FromX509Certificate(issuer));
            certificateGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier.Id, false, authorityKeyIdentifier);

            certificateGenerator.AddExtension(X509Extensions.KeyUsage.Id, false,
                new KeyUsage(KeyUsage.DataEncipherment | KeyUsage.KeyEncipherment | KeyUsage.DigitalSignature));

            GeneralNames subjectAltName = new GeneralNames(new GeneralName(GeneralName.DnsName, "localhost"));
            certificateGenerator.AddExtension(X509Extensions.SubjectAlternativeName, false, subjectAltName);

            certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage.Id, false,
                new ExtendedKeyUsage(new List<DerObjectIdentifier> { new DerObjectIdentifier("1.3.6.1.5.5.7.3.1") }));

            var issuerKeyPair = issuer == null
                ? keyPair
                : DotNetUtilities.GetKeyPair(issuer.PrivateKey);

            var signatureFactory = new Asn1SignatureFactory(ALGORITHM, issuerKeyPair.Private, random);
            var newCert = certificateGenerator.Generate(signatureFactory);
            return new X509Certificate2(newCert.GetEncoded())
            {
                PrivateKey = ToDotNetKey((RsaPrivateCrtKeyParameters)keyPair.Private)
            };
        }

        private static AsymmetricAlgorithm ToDotNetKey(RsaPrivateCrtKeyParameters privateKey)
        {
            var keyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
            var seq = (Asn1Sequence)Asn1Object.FromByteArray(keyInfo.ParsePrivateKey().GetDerEncoded());
            if (seq.Count != 9)
                throw new Exception("Malformed sequence in RSA private key");

            var rsa = RsaPrivateKeyStructure.GetInstance(seq);
            var rsaParams = new RsaPrivateCrtKeyParameters(
                rsa.Modulus, rsa.PublicExponent, rsa.PrivateExponent,
                rsa.Prime1, rsa.Prime2, rsa.Exponent1,
                rsa.Exponent2, rsa.Coefficient);

            var cspParams = new CspParameters
            {
                KeyContainerName = Guid.NewGuid().ToString(),
                KeyNumber = (int)KeyNumber.Exchange,
                Flags = CspProviderFlags.UseMachineKeyStore
            };

            return DotNetUtilities.ToRSA(rsaParams, cspParams);
        }

        private static void RunElevated()
        {
            var info = new ProcessStartInfo(Assembly.GetEntryAssembly().Location,
                string.Join(" ", Enumerable.Concat(Program.Args, new[] { "admin" })))
            {
                UseShellExecute = true,
                Verb = "runas",
            };

            var process = new Process
            {
                EnableRaisingEvents = true,
                StartInfo = info
            };

            process.Start();
        }
    }

}
