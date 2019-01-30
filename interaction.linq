<Query Kind="Program">
  <NuGetReference>BouncyCastle</NuGetReference>
  <NuGetReference>Nancy</NuGetReference>
  <NuGetReference>Nancy.Hosting.Self</NuGetReference>
  <Namespace>System.Security.Cryptography</Namespace>
  <Namespace>System.Security.Cryptography.X509Certificates</Namespace>
  <Namespace>Nancy.Hosting.Self</Namespace>
  <Namespace>Nancy</Namespace>
  <Namespace>Org.BouncyCastle.Crypto.Prng</Namespace>
  <Namespace>Org.BouncyCastle.Security</Namespace>
  <Namespace>Org.BouncyCastle.X509</Namespace>
  <Namespace>Org.BouncyCastle.Utilities</Namespace>
  <Namespace>Org.BouncyCastle.Math</Namespace>
  <Namespace>Org.BouncyCastle.Asn1.X509</Namespace>
  <Namespace>Org.BouncyCastle.X509.Extension</Namespace>
  <Namespace>Org.BouncyCastle.Crypto</Namespace>
  <Namespace>Org.BouncyCastle.Crypto.Generators</Namespace>
  <Namespace>Org.BouncyCastle.Crypto.Operators</Namespace>
  <Namespace>Org.BouncyCastle.Crypto.Parameters</Namespace>
  <Namespace>Org.BouncyCastle.Asn1</Namespace>
  <Namespace>Org.BouncyCastle.Pkcs</Namespace>
  <Namespace>Org.BouncyCastle.Asn1.Pkcs</Namespace>
  <Namespace>System.Runtime.InteropServices</Namespace>
</Query>

public const int HTTPPORT = 40849;
public const int HTTPSPORT = 40850;

void Main(string[] args)
{
	if (!IsUserAnAdmin())
	{
		//You can remove this line after first run, admin righst is required only once to setup a ssl certificate
		Console.WriteLine("Admin rights is required, please run LINQPad as an administrator");
		return;
	}

	var certSubjectName = "CsClientApp SSL Certificate";
	var rootSubjectName = "CsClientApp Root CA";
	SslHelper.CheckOrCreateCertificates(certSubjectName, rootSubjectName);

	var hostConfigs = new HostConfiguration();
	hostConfigs.UrlReservations.CreateAutomatically = true;
	hostConfigs.RewriteLocalhost = false;

	var uris = new Uri[]
	{
				new Uri($"http://localhost:{HTTPPORT}"),
				new Uri($"http://127.0.0.1:{HTTPPORT}"),
				new Uri($"https://localhost:{HTTPSPORT}")
	};
	using (var host = new NancyHost(hostConfigs, uris))
	{
		host.Start();

		Console.WriteLine("Listening on:");
		foreach (var uri in uris)
		{
			Console.WriteLine(uri.ToString());
		}
		Util.ReadLine();
	}
}

[DllImport("shell32.dll")] public static extern bool IsUserAnAdmin();

public class CalcNancyModule : NancyModule
{
	public CalcNancyModule()
	{
		After.AddItemToEndOfPipeline((ctx) => ctx.Response
			 .WithHeader("Access-Control-Allow-Origin", GetOrigin(ctx))
			 .WithHeader("Access-Control-Allow-Methods", "POST,GET")
			 .WithHeader("Access-Control-Allow-Headers", "Accept, Origin, Content-type"));

		Get["/Calc"] = _ =>
		{
			//Simaulate hard work...
			Thread.Sleep(1000);

			var assemblyVersion = Assembly.GetExecutingAssembly().GetName().Version.ToString();
			return $"{{ \"version\": \"{assemblyVersion}\" }}";
		};
		Get["/Calc/Add"] = _ =>
		{
			//Simaulate hard work...
			Thread.Sleep(1000);

			var num1String = Request.Query["num1"] ?? "";
			var num2String = Request.Query["num2"] ?? "";

			var parsed1 = int.TryParse(num1String, out int num1);
			var parsed2 = int.TryParse(num2String, out int num2);
			var parsed = parsed1 && parsed2;

			if (parsed)
				return $"{{ \"result\": \"{num1 + num2}\" }}";
			else
				return $"{{ \"error\": \"can't parse input values\" }}";
		};
	}

	private string GetOrigin(NancyContext ctx)
	{
		return ctx.Request?.Headers["Origin"]?.FirstOrDefault() ?? "";
	}
}


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
				$"http delete sslcert ipport=0.0.0.0:{HTTPSPORT}",
				$"http add sslcert ipport=0.0.0.0:{HTTPSPORT} certhash={certThumbprint} appid=\"{AppId}\""
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
}