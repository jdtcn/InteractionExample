using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Text;
using Nancy.Hosting.Self;


namespace CsClientApp
{
    class Program
    {
        public const int HTTPPORT = 40849;
        public const int HTTPSPORT = 40850;

        public static string[] Args { get; set; }
        public static bool IsElevated { get; set; }

        static void Main(string[] args)
        {
            Args = args;
            IsElevated = args.Contains("admin");

            var certSubjectName = "CsClientApp SSL Certificate";
            var rootSubjectName = "CsClientApp Root CA";
            var cert = SslHelper.CheckOrCreateCertificates(certSubjectName, rootSubjectName);
            if (cert == null)
            {
                return;
            }

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
                Console.ReadKey();
            }
        }
    }
}
