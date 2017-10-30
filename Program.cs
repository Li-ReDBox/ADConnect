using System;
using System.IO;
using System.Collections.Generic;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using Novell.Directory.Ldap;

namespace novell.ldap
{
    /// <summary>
    /// Default values and functions for the namespace
    /// </summary>
    static class DEFAULTS {
        // To describe an account
        public static string[] BASIC_PROPERTIES = {"cn", "uidNumber", "company", "department", "telephonenumber"};
        // For checking new account
        public static string[] CREATION_PROPERTIES = {"cn", "uidnumber", "whencreated", "mail"};

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
        public static bool CertificateValidationCallBack(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
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
    }

    public class Utils {
        protected string CrateFilter(string whenCreated) {
            // https://msdn.microsoft.com/en-us/library/aa746475(v=vs.85).aspx
            return "(&(objectCategory=User)(objectClass=User)(objectClass=Person)(!(objectClass=Computer))(mail=*@*)(!(mail=*ersa.edu.au))(whenCreated>=" + whenCreated + "))";
        }

        /// <summary>
        /// Convert ResultPropertyCollection to Dictionary
        /// </summary>
        /// <param name="searchResult">SearchResult</param>
        /// <returns>Dictionary</returns>
        protected static Dictionary<string, string> GetProperties(LdapAttributeSet searchResult)
        {
            if (searchResult == null) return null;

            Dictionary<string, string> filtered = new Dictionary<string, string>();

            // Our checking logic depends on uidnumber
            if (searchResult.getAttribute("uidnumber") == null)
                throw new NullReferenceException(string.Format("{0} has no uidnumber", searchResult.getAttribute("cn")));

            foreach(LdapAttribute attribute in searchResult) {
                Console.WriteLine(attribute.Name + "value:" + attribute.StringValue);
                filtered[attribute.Name] = attribute.StringValue;
            }

            return filtered;
        }
    }

    /// <summary>
    /// Interface to provide search functions against active directories
    /// </summary>
    public interface IADSearcher
    {
        /// <summary>
        /// Search in AD for non-eRSA accounts created after a given date
        /// </summary>
        /// <param name="earliest"></param>
        List<Dictionary<string, string>> Search(DateTime earliest);

        /// <summary>
        /// Get a full description a User
        /// </summary>
        /// <param name="username"></param>
        /// <returns>Dictionary of user information or null</returns>
        Dictionary<string, string> GetUser(int uidNumber, bool all=false);
    }

    public class NovellLdap : Utils, IADSearcher, IDisposable
    {
        private LdapConnection conn;
        public NovellLdap(IConfigurationRoot configuration) {
            bool useSSL;
            Boolean.TryParse(configuration["UseSSL"], out useSSL);

            string ldapHost = configuration["Host"];
            int ldapPort = Int16.Parse(configuration["Port"]);
            String loginDN = configuration["LoginDN"];
            String password = configuration["Password"];
            conn = new LdapConnection();
            if (useSSL) {
                conn.SecureSocketLayer = true;
            }
            conn.ConnectionTimeout = 300;

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
                    conn.UserDefinedServerCertValidationDelegate += DEFAULTS.CertificateValidationCallBack;
                }
            }
            conn.Bind(loginDN, password);
        }

        /// <summary>
        /// Search in AD for non-eRSA accounts created after a given date
        /// Only display selected attributes defined in _essentialProperties
        /// </summary>
        /// <param name="earliest"></param>
        public List<Dictionary<string, string>> Search(DateTime earliest)
        {
            string whenCreated = earliest.ToUniversalTime().ToString("yyyyMMddHHmmss.0Z");
            Console.WriteLine("Local {0} to UTC {1}", earliest, whenCreated);

            string userFilter = CrateFilter(whenCreated);

            List<Dictionary<string, string>> results = new List<Dictionary<string, string>>();
            // Searches in the Marketing container and return all child entries just below this
            //container i.e. Single level search
            LdapSearchResults lsc = conn.Search("DC=ad,DC=ersa,DC=edu,DC=au",
                LdapConnection.SCOPE_SUB,
                userFilter,
                DEFAULTS.BASIC_PROPERTIES,
                false);

            int count = 0;
            while (lsc.hasMore())
            {
                LdapEntry nextEntry = null;
                try
                {
                    nextEntry = lsc.next();
                    count++;
                }
                catch (LdapReferralException) {
                    // Nothing really serious: constraints.ReferralFollowing = true this may not be needed
                    // https://www.novell.com/documentation/developer/ldapcsharp/?page=/documentation/developer/ldapcsharp/cnet/data/b3u4u0n.html
                    // https://technet.microsoft.com/en-us/library/cc978014.aspx
                    continue;
                }
                catch (LdapException e)
                {
                    Console.WriteLine("Move next error: {0}", e.ToString());
                    Console.WriteLine("Error message: " + e.Message);
                    continue;
                }
                Console.WriteLine("\n" + nextEntry.DN);
                try {
                    results.Add(GetProperties(nextEntry.getAttributeSet()));
                } catch (NullReferenceException ex)
                {
                    Console.WriteLine("Not a qualified person account");
                    Console.WriteLine(ex.Message);
                }
            }
            return results;
        }

        public Dictionary<string, string> GetUser(int uidnumber, bool all=false)
        {
            string filter = string.Format("(uidNumber={0})", uidnumber);
            string[] properties = { };
            if (!all) {
                properties = DEFAULTS.BASIC_PROPERTIES;
            }
            return new Dictionary<string, string>();
        }

        public void Dispose() {
            if (conn != null) conn.Disconnect();
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Runtime is Linux = {0}", System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Linux));
            IConfigurationRoot configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("ad_connection.json")
                .Build();

            DateTime earliest = new DateTime(2017, 1, 1);
            using (NovellLdap novell = new NovellLdap(configuration)) {
                try {
                    List<Dictionary<string, string>> results = novell.Search(earliest);
                    Console.WriteLine(results.Count);
                } catch (Exception e) {
                    Console.WriteLine(e.ToString());
                }
            };
        }
    }
}
