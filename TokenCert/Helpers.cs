using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using static TokenCert.Advapi32;

namespace TokenCert
{
    internal class Helpers
    {
        public static bool Rev2Self()
        {
            if (!Advapi32.RevertToSelf())
            {
                Console.WriteLine($"[!] RevertToSelf() Error: 0x{Marshal.GetLastWin32Error():X}" );
                return false;
            }
            Console.WriteLine("[*] Successfully reverted back");
            try
            {
                Advapi32.LUID newLuid = GetCurrentLUID();
                Console.WriteLine($"[*] Current LogonID (LUID) : {newLuid} ({(UInt64)newLuid})\r\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error retrieving current LUID: {ex.Message}");
                return false;
            }
            return true;
        }

        public static string NameFromCert(X509Certificate2 cert)
        {
            string name = cert.GetNameInfo(X509NameType.UpnName, false);
            if (String.IsNullOrEmpty(name))
            {
                string dnsName = cert.GetNameInfo(X509NameType.DnsName, false);
                if (!string.IsNullOrEmpty(dnsName))
                {
                    var dnsParts = dnsName.Split('.');
                    name = dnsParts.Length > 0 ? dnsParts[0] + "$" : dnsName + "$";
                }
                else
                {
                    throw new Exception("[!] Certificate does not contain a UPN or DNS Name.");
                }
            }
            else
            {
                name = name.Split('@')[0];
            }

            return name;
        }
        public static string MarshalCertificate(X509Certificate2 cert)
        {
            CERT_CREDENTIAL_INFO certInfo = new CERT_CREDENTIAL_INFO
            {
                cbSize = (uint)Marshal.SizeOf(typeof(CERT_CREDENTIAL_INFO)),
                rgbHashOfCert = cert.GetCertHash()
            };

            IntPtr pCertInfo = Marshal.AllocHGlobal(Marshal.SizeOf(certInfo));
            IntPtr marshaledCredential = IntPtr.Zero;
            try
            {
                Marshal.StructureToPtr(certInfo, pCertInfo, false);

                bool result = CredMarshalCredential(CRED_MARSHAL_TYPE.CertCredential, pCertInfo, out marshaledCredential);

                if (!result)
                {
                    throw new Exception($"[!] CredMarshalCredential failed with error code: 0x{Marshal.GetLastWin32Error():X}");
                }

                string username = Marshal.PtrToStringUni(marshaledCredential);
                return username;
            }
            finally
            {
                Marshal.FreeHGlobal(pCertInfo);
                if (marshaledCredential != IntPtr.Zero)
                {
                    CredFree(marshaledCredential);
                }
            }
        }
        public static Advapi32.LUID GetCurrentLUID()
        {
            var TokenInfLength = 0;
            var luid = new Advapi32.LUID();
            bool result = Advapi32.GetTokenInformation(WindowsIdentity.GetCurrent().Token, Advapi32.TOKEN_INFORMATION_CLASS.TokenStatistics, IntPtr.Zero, TokenInfLength, out TokenInfLength);

            var TokenInformation = Marshal.AllocHGlobal(TokenInfLength);
            try
            {
                result = Advapi32.GetTokenInformation(WindowsIdentity.GetCurrent().Token,Advapi32.TOKEN_INFORMATION_CLASS.TokenStatistics,TokenInformation,TokenInfLength,out TokenInfLength);

                if (result)
                {
                    var TokenStatistics = Marshal.PtrToStructure<Advapi32.TOKEN_STATISTICS>(TokenInformation);
                    luid = new Advapi32.LUID(TokenStatistics.AuthenticationId);
                }
                else
                {
                    Console.WriteLine($"[!] GetTokenInformation error: 0x{Marshal.GetLastWin32Error():X}");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(TokenInformation);
            }

            return luid;
        }
        public static string GetEnhancedKeyUsages(X509Certificate2 cert)
        {
            if (cert == null) throw new ArgumentNullException(nameof(cert));

            var eku = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
            if (eku != null)
            {
                StringBuilder sb = new StringBuilder();
                foreach (var oid in eku.EnhancedKeyUsages)
                {
                    sb.AppendLine($"  {oid.FriendlyName} ({oid.Value})");
                }
                return sb.ToString();
            }
            return null;
        }
        public static string GetSubjectAlternativeNames(X509Certificate2 cert)
        {
            foreach (var extension in cert.Extensions)
            {
                if (extension.Oid.Value == "2.5.29.17")
                {
                    var asnData = new AsnEncodedData(extension.Oid, extension.RawData);
                    return asnData.Format(true);
                }
            }
            return null;
        }
        public static string DescribeCertificate(X509Certificate2 cert)
        {
            if (cert == null) throw new ArgumentNullException(nameof(cert));

            StringBuilder sb = new StringBuilder();

            sb.AppendLine("\n[+] Certificate Information:");
            sb.AppendLine($"    Subject: {cert.Subject}");
            sb.AppendLine($"    Issuer: {cert.Issuer}");
            sb.AppendLine($"    Valid From: {cert.NotBefore}");
            sb.AppendLine($"    Valid To: {cert.NotAfter}");
            sb.AppendLine($"    Thumbprint: {cert.Thumbprint}");
            sb.AppendLine($"    Serial Number: {cert.SerialNumber}");
            sb.AppendLine($"    Version: {cert.Version}");
            sb.AppendLine($"    Signature Algorithm: {cert.SignatureAlgorithm.FriendlyName}");
            sb.AppendLine($"    Public Key Algorithm: {cert.PublicKey.Oid.FriendlyName}");
            sb.AppendLine($"    Has Private Key: {cert.HasPrivateKey}");

            string san = GetSubjectAlternativeNames(cert);
            if (!string.IsNullOrEmpty(san))
            {
                sb.AppendLine("\n[+] Subject Alternative Names:");
                sb.AppendLine(san);
            }

            string eku = GetEnhancedKeyUsages(cert);
            if (!string.IsNullOrEmpty(eku))
            {
                sb.AppendLine("\n[+] Enhanced Key Usages:");
                sb.AppendLine(eku);
            }

            var keyUsage = cert.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
            if (keyUsage != null)
            {
                sb.AppendLine($"[+] Key Usages: {keyUsage.KeyUsages}");
            }
            var basicConstraints = cert.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
            if (basicConstraints != null)
            {
                sb.AppendLine($"\n[+] Certificate Authority: {basicConstraints.CertificateAuthority}");
                sb.AppendLine($"\n[+] Has Path Length Constraint: {basicConstraints.HasPathLengthConstraint}");
                sb.AppendLine($"\n[+] Path Length Constraint: {basicConstraints.PathLengthConstraint}");
            }

            return sb.ToString();
        }
    }
}
