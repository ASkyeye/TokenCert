using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using TokenCert;

namespace TokenCert
{
    class Program
    {
        public static void MakeToken(string base64Cert, string domain, string password = "")
        {
            IntPtr hProcessToken = IntPtr.Zero;
            X509Certificate2 cert = null;
            try
            {
                byte[] certData = Convert.FromBase64String(base64Cert);
                cert = new X509Certificate2(certData, password, X509KeyStorageFlags.PersistKeySet);

                Console.WriteLine(Helpers.DescribeCertificate(cert));

                using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
                {
                    store.Open(OpenFlags.ReadWrite);
                    store.Add(cert);
                }
                string username = Helpers.MarshalCertificate(cert);
                var user = Helpers.NameFromCert(cert);

                var logonType = Advapi32.LOGON_TYPE.LOGON32_LOGON_NEW_CREDENTIALS;
                var logonProvider = Advapi32.LOGON_PROVIDER.LOGON32_PROVIDER_DEFAULT;

                Advapi32.LUID currentLuid = Helpers.GetCurrentLUID();
                Console.WriteLine($"[*] Current LogonID (LUID) : {currentLuid} ({(UInt64)currentLuid})\r\n");
                Console.WriteLine($"[*] Making token as user {domain}\\{user}");

                if (!Advapi32.LogonUserA(username, domain, null, logonType, logonProvider, out hProcessToken))
                {
                    Console.WriteLine("[!] LogonUserA() Error: " + Marshal.GetLastWin32Error());
                    return;
                }

                if (!Advapi32.ImpersonateLoggedOnUser(hProcessToken))
                {
                    Console.WriteLine("[!] ImpersonateLoggedOnUser() Error: " + Marshal.GetLastWin32Error());
                    Advapi32.CloseHandle(hProcessToken);
                    return;
                }
                Console.WriteLine("[*] Token applied successfully");
                Advapi32.LUID newLuid = Helpers.GetCurrentLUID();
                Console.WriteLine($"[*] Current LogonID (LUID) : {newLuid} ({(UInt64)newLuid})");

            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] An exception occured: {ex.Message} Stack Trace:{ex.StackTrace}");
            }
            finally
            {
                if (cert != null)
                {
                    using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
                    {
                        store.Open(OpenFlags.ReadWrite);
                        X509Certificate2Collection certCollection = store.Certificates.Find(
                        X509FindType.FindByThumbprint,
                            cert.Thumbprint,
                            validOnly: false);

                        foreach (X509Certificate2 certToRemove in certCollection)
                        {
                            store.Remove(certToRemove);
                        }
                    }
                    cert.Dispose();
                }
                if (hProcessToken != IntPtr.Zero)
                {
                    Advapi32.CloseHandle(hProcessToken);
                }
            }
        }
        static void Main(string[] args)
        {
            string certificate = null;
            string domain = null;
            string password = "";

            if (args.Length == 0)
            {
                ShowUsage();
                return;
            }

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i].Equals("-Cert", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                {
                    certificate = args[++i];
                }
                else if (args[i].Equals("-Domain", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                {
                    domain = args[++i];
                }
                else if (args[i].Equals("-Password", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                {
                    password = args[++i];
                }
                else if (args[i].Equals("rev2self", StringComparison.OrdinalIgnoreCase))
                {
                    Helpers.Rev2Self();
                    return;

                }
                else
                {
                    Console.WriteLine("[!] Unknown argument: " + args[i]);
                    ShowUsage();
                    return;
                }
            }

            if (certificate == null || domain == null)
            {
                Console.WriteLine("[!] Certificate and Domain are required.");
                ShowUsage();
                return;
            }

            try
            {
                MakeToken(certificate, domain, password);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] An exception occured: {ex.Message} Stack Trace:{ex.StackTrace}");
            }
          
        }

        static void ShowUsage()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("tokencert.exe -Cert <base64> -Domain <domain> [-Password <password>]");
            Console.WriteLine("tokencert.exe rev2self");
        }
    }
}
