using System;
using System.Collections.Generic;
using Microsoft.Extensions.Configuration;
using System.DirectoryServices;

namespace ADConnectors
{
    class AD : IADSearcher
    {
        DirectoryEntry _domain;

        public AD(IConfiguration configuration)
        {
            string domainName = configuration["Host"];
            string userName = configuration["Username"];
            string passwd = configuration["Password"];

            Boolean.TryParse(configuration["UseSSL"], out bool useSSL);
            Boolean.TryParse(configuration["ForceSSL"], out bool forceSSL);
            string protocol = "LDAP://";
            if (useSSL) protocol = "LDAPS://";
            // FIXME: cannot use LDAPS yet
            ConnectAD(domainName, userName, passwd);
        }

        public AD(string domainName, string userName = "", string passwd = "")
        {
            ConnectAD(domainName, userName, passwd);
        }

        private void ConnectAD(string domainName, string userName, string passwd)
        {
            if (userName != "" && passwd != "")
            {
                Console.WriteLine("username and password were set");
                _domain = new DirectoryEntry("LDAP://" + domainName, userName, passwd);
            }
            else
            {
                _domain = new DirectoryEntry("LDAP://" + domainName);
            }
            if (_domain == null)
            {
                new System.ArgumentException(String.Format("Cannot connect to {0}, check arguments", _domain));
            }
            Console.WriteLine("Domain properties:");

            foreach (string propName in _domain.Properties.PropertyNames)
            {
                Console.WriteLine("{0:-20d}: {1}", propName, _domain.Properties[propName][0]);
            }
        }

        /// <summary>
        /// Convert ResultPropertyCollection to Dictionary
        /// </summary>
        /// <param name="searchResult">SearchResult</param>
        /// <returns>Dictionary</returns>
        private static Dictionary<string, string> GetProperties(SearchResult searchResult)
        {
            if (searchResult == null) return null;

            Dictionary<string, string> filtered = new Dictionary<string, string>();
            ResultPropertyCollection resultPropColl = searchResult.Properties;

            // Our checking logic depends on uidnumber
            if (!resultPropColl.Contains("uidnumber"))
                throw new NullReferenceException(string.Format("{0} has no uidnumber", resultPropColl["cn"][0]));
            foreach (string propKey in resultPropColl.PropertyNames)
            {
                //Console.WriteLine("{0}:{1}", propKey, resultPropColl[propKey][0].ToString());
                // Only get the first property in the keyed collection: only objectclass missing information by doing so
                filtered[propKey] = resultPropColl[propKey][0].ToString();
            }
            return filtered;
        }

        /// <summary>
        /// List full property set of a SearchResult for debugging purpose
        /// </summary>
        /// <param name="searchResult">SearchResult</param>
        private static void ListProperties(SearchResult searchResult)
        {
            ResultPropertyCollection resultProperties = searchResult.Properties;
            Console.WriteLine("The properties AD search result are :");

            foreach (string propKey in resultProperties.PropertyNames)
            {
                string tab = "    ";
                Console.WriteLine(propKey + " = ");
                foreach (Object myCollection in resultProperties[propKey])
                {
                    Console.WriteLine(tab + myCollection);
                }
            }
        }

        /// <summary>
        /// List full property set of a DirectoryEntry for debugging purpose
        /// </summary>
        /// <param name="resEnt">DirectoryEntry</param>
        /// <returns></returns>
        private static void ListProperties(DirectoryEntry resEnt)
        {
            foreach (string propKey in resEnt.Properties.PropertyNames)
            {
                Console.WriteLine("{0}:{1}", propKey, resEnt.Properties[propKey][0]);
            }
        }

        // Install-Package System.DirectoryServices -Source https://dotnet.myget.org/F/dotnet-core/api/v3/index.json
        /// <summary>
        /// Search non-eRSA user created after given earliest
        /// Only display selected attributes defined in HELPER.CREATION_PROPERTIES
        /// </summary>
        /// <param name="earliest"></param>
        public List<Dictionary<string, string>> Search(DateTime earliest)
        {
            Console.WriteLine($"Start to search for accounts created after {earliest}");
            Console.WriteLine(_domain.Name);
            List<Dictionary<string, string>> results = new List<Dictionary<string, string>>();
            try
            {
                // Format DateTime object to a datetime string in AD-LDAP format
                // https://social.technet.microsoft.com/wiki/contents/articles/28222.active-directory-generalized-time-attributes.aspx
                // https://stackoverflow.com/questions/10391174/query-ldap-for-all-computer-objects-created-in-the-last-24-hours
                string whenCreated = earliest.ToUniversalTime().ToString("yyyyMMddHHmmss.0Z");
                Console.WriteLine("Local {0} to UTC {1}", earliest, whenCreated);

                int count = 0;
                // https://technet.microsoft.com/en-us/library/aa996205(v=exchg.65).aspx#DoingASearchUsingADUC
                string userFilter = HELPER.CrateFilter(whenCreated);
                using (DirectorySearcher newAccounts = new DirectorySearcher(_domain, userFilter, HELPER.CREATION_PROPERTIES))
                {
                    foreach (SearchResult res in newAccounts.FindAll())
                    {
                        try
                        {
                            results.Add(GetProperties(res));
                            count++;
                        }
                        catch (NullReferenceException ex)
                        {
                            Console.WriteLine(ex.Message);
                        }
                    }
                    Console.WriteLine($"Total user found: {count}");
                }
            }
            catch (System.Exception ex)
            {
                Console.WriteLine("Search failed, see exception below:");
                Console.WriteLine(ex.ToString());
            }
            return results;
        }

        /// <summary>
        /// Get a full description a User
        /// </summary>
        /// <param name="uidnumber"></param>
        /// <returns>A dictionary or null</returns>
        public Dictionary<string, string> GetUser(int uidnumber, bool all=false)
        {
            string filter = string.Format("(uidnumber={0})", uidnumber);
            string[] properties = { };
            if (!all) {
                properties = HELPER.BASIC_PROPERTIES;
            }
            using (DirectorySearcher adSearch = new DirectorySearcher(_domain, filter, properties))
            {
                SearchResult adSearchResult = adSearch.FindOne();
                return GetProperties(adSearchResult);
            }
        }
    }
}
