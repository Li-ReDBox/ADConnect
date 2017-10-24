using System;
using System.IO;
// using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using Novell.Directory.Ldap;

namespace novell.ldap
{
    class Program
    {
 private static bool CertificateValidationCallBack(object sender,
         System.Security.Cryptography.X509Certificates.X509Certificate certificate,
         System.Security.Cryptography.X509Certificates.X509Chain chain,
         System.Net.Security.SslPolicyErrors sslPolicyErrors)
    {
        Console.WriteLine("IssuerName = {0}, Subject = {1}, EffectiveDate = {2}", certificate.Issuer, certificate.Subject, certificate.GetEffectiveDateString());
        return certificate.GetRawCertData() != null;
    }

        static void Main(string[] args)
        {
            IConfigurationRoot configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("ad_connection.json")
                .Build();

            bool useSSL;
            Boolean.TryParse(configuration["UseSSL"], out useSSL);
            Console.WriteLine(useSSL);

            string ldapHost = configuration["Host"];
            int ldapPort = Int16.Parse(configuration["Port"]);
            String loginDN = configuration["LoginDN"];
            String password = configuration["Password"];
            LdapConnection conn= new LdapConnection();
            // int ldapPort = 636;
            if (useSSL) {
                conn.SecureSocketLayer = true;
                conn.UserDefinedServerCertValidationDelegate += CertificateValidationCallBack;
            }
            conn.ConnectionTimeout = 300;
            Console.WriteLine("Connecting to:" + ldapHost);
            int count = 0;
            try {
                conn.Connect(ldapHost, ldapPort);
                Console.WriteLine("Try to bind");
                conn.Bind(loginDN, password);
                Console.WriteLine("Bind finished");

                DateTime earliest = new DateTime(2017, 1, 1);
                string whenCreated = earliest.ToUniversalTime().ToString("yyyyMMddHHmmss.0Z");
                Console.WriteLine("Local {0} to UTC {1}", earliest, whenCreated);

                // https://msdn.microsoft.com/en-us/library/aa746475(v=vs.85).aspx
                string userFilter = "(&(objectCategory=User)(objectClass=User)(objectClass=Person)(!(objectClass=Computer))(mail=*@*)(!(mail=*ersa.edu.au))(whenCreated>=" + whenCreated + "))";

                // Searches in the Marketing container and return all child entries just below this
                //container i.e. Single level search
                LdapSearchResults lsc = conn.Search("DC=ad,DC=ersa,DC=edu,DC=au", LdapConnection.SCOPE_SUB, userFilter, null, false);
                while (lsc.hasMore())
                {
                    LdapEntry nextEntry = null;
                    try
                    {
                        nextEntry = lsc.next();
                        count++;
                    }
                    catch (LdapException e)
                    {
                        Console.WriteLine("Move next error: " + e.LdapErrorMessage);
                        // Exception is thrown, go for next entry
                        continue;
                    }
                    Console.WriteLine("\n" + nextEntry.DN);
                    foreach(LdapAttribute attribute in nextEntry.getAttributeSet()) {
                        string attributeName = attribute.Name;
                        string attributeVal = attribute.StringValue;
                        Console.WriteLine(attributeName + "value:" + attributeVal);
                    }
                }
            } catch (Exception e) {
                Console.WriteLine("Your search has problems");
                Console.WriteLine(e.ToString());
            }
            Console.WriteLine($"Total number of new account = {count}");
            conn.Disconnect();
        }
    }
}
