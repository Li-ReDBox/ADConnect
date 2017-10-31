To work around lacking of support of LDAP functions in .Net Core 2.0
use [Novell.Directory.Ldap.NETStandard](https://github.com/dsbenghe/Novell.Directory.Ldap.NETStandard).
See details [here](https://github.com/dotnet/corefx/issues/2089) for background and progress.

The project needs these dependencies:

```shell
dotnet add package Microsoft.Extensions.Configuration
dotnet add package Microsoft.Extensions.Configuration.Json
dotnet add package Novell.Directory.Ldap.NETStandard --version 2.3.8
dotnet add package System.DirectoryServices --version 4.5.0-preview2-25707-02 --source https://dotnet.myget.org/F/dotnet-core/api/v3/index.json
```

## Configure how to connect AD
The applicaion needs `ad_connection.json` with these keys to connect AD var LDAP:

```json
{
    "Host": "ad.server",
    "Port": 636,
    "LoginDN": "CN=user,DC=edu,DC=au",
    "Password": "password",
    "UseSSL": true,
    "ForceSSL": false
}
```

`ForceSSL` is optional, which default is false. `UseSSL` can be omitted but SHOULD not do it.

## Connect to AD over ssl

Ideally, we should be able to connect AD from client side with this:
`
  _domain = new DirectoryEntry("LDAP://" + domainName, userName, passwd, AuthenticationTypes.SecureSocketsLayer | AuthenticationTypes.FastBind);
`

But (possibly) because of certification problems, it is not possible to do it with `System.DirectoryServices` as it does not have ways to deal with
certification errors like Novel library. Some references may be useful are:

1. https://social.technet.microsoft.com/Forums/en-US/0d19f956-b8ce-4b3e-b987-cbba83fd89cc/powershell-and-ldaps?forum=ITCG
1. https://stackoverflow.com/questions/43867464/cannot-connect-to-ad-lds-with-ssl-using-powershell
1. https://support.microsoft.com/en-us/help/321051/how-to-enable-ldap-over-ssl-with-a-third-party-certification-authority
1. https://social.technet.microsoft.com/wiki/contents/articles/2980.ldap-over-ssl-ldaps-certificate.aspx
1. https://blogs.technet.microsoft.com/askds/2008/03/13/troubleshooting-ldap-over-ssl/
