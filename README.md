To work around lacking of support of LDAP functions in .Net Core 2.0
use [Novell.Directory.Ldap.NETStandard](https://github.com/dsbenghe/Novell.Directory.Ldap.NETStandard).
See details [here](https://github.com/dotnet/corefx/issues/2089) for background and progress.

The project needs these dependencies:

```shell
dotnet add package Microsoft.Extensions.Configuration
dotnet add Microsoft.Extensions.Configuration.Json
dotnet add package Novell.Directory.Ldap.NETStandard --version 2.3.8
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