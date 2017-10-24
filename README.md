To work around lacking of support of LDAP functions, see [details](https://github.com/dotnet/corefx/issues/2089)
use [Novell.Directory.Ldap.NETStandard](https://github.com/dsbenghe/Novell.Directory.Ldap.NETStandard):

```shell
dotnet add package Microsoft.Extensions.Configuration
dotnet add Microsoft.Extensions.Configuration.Json
dotnet add package Novell.Directory.Ldap.NETStandard --version 2.3.8
```