using System;
using System.IO;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using Novell.Directory.Ldap;

namespace novell.ldap
{
    class Program
    {
        /// <summary>
        /// Validates the SSL server certificate ourselves.
        /// When this is used, there is something wrong with certs. So use this to check then decide how to deal it
        /// if no one can fix the cert problem:
        /// openssl s_client -connect remotehost:port
        /// </summary>
        /// <param name="sender">An object that contains state information for this
        /// validation.</param>
        /// <param name="cert">The certificate used to authenticate the remote party.</param>
        /// <param name="chain">The chain of certificate authorities associated with the
        /// remote certificate.</param>
        /// <param name="sslPolicyErrors">One or more errors associated with the remote
        /// certificate.</param>
        /// <returns>Returns a boolean value that determines whether the specified
        /// certificate is accepted for authentication; true to accept or false to
        /// reject.</returns>
        private static bool CertificateValidationCallBack(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            Console.WriteLine("AD server's certification has not passed the default checking,");
            Console.WriteLine("\tHere are some more information for you to check.");
            Console.WriteLine($"\tIssuerName = {certificate.Issuer}");
            Console.WriteLine($"\tSubject = {certificate.Issuer}, EffectiveDate = {2}");
            Console.WriteLine($"\tEffectiveDate = {certificate.GetEffectiveDateString()}");
            Console.WriteLine($"\tHash string: {certificate.GetCertHashString()}");
            Console.WriteLine("Here are some of certification errors just for you to fix it:");
            // https://msdn.microsoft.com/en-us/library/office/jj900163(v=exchg.150).aspx shows how to not reject self-signed
            if (chain != null && chain.ChainStatus != null)
            {
                foreach (X509ChainStatus status in chain.ChainStatus)
                {
                    Console.WriteLine($"\tStatus: {status.StatusInformation}");
                }
            }
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

            string ldapHost = configuration["Host"];
            int ldapPort = Int16.Parse(configuration["Port"]);
            String loginDN = configuration["LoginDN"];
            String password = configuration["Password"];
            LdapConnection conn= new LdapConnection();
            if (useSSL) {
                conn.SecureSocketLayer = true;
            }
            conn.ConnectionTimeout = 300;
            Console.WriteLine($"Connecting to: {ldapHost}");
            int count = 0;
            try {
                try {
                    conn.Connect(ldapHost, ldapPort);
                } catch (System.Security.Authentication.AuthenticationException e) {
                    Console.WriteLine("Default certification check failed:");
                    Console.WriteLine($"\t{e.Message}");
                    bool forceSSL;
                    Boolean.TryParse(configuration["ForceSSL"], out forceSSL);
                    if (forceSSL) {
                        Console.WriteLine("Because ForceSSL is `true`, please fix certification or authentication error before try again.");
                        return;
                    } else {
                        Console.WriteLine("\ttry to by pass it!");
                        conn.UserDefinedServerCertValidationDelegate += CertificateValidationCallBack;
                    }
                }

                conn.Bind(loginDN, password);

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
