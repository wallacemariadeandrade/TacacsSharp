# TacacsSharp
A TACACS+ client built on .NET Standard using C#. Based on [this](https://tools.ietf.org/html/draft-ietf-opsawg-tacacs-11) IETF Internet-Draft.

### Simple Authentication Example

```C#
// TACACS+ server configuration info
string serverIP = "192.168.18.19";
int serverPort = 49;
string sharedKey = "test";

// User info
string username = "tacacsSharp";
string password = "changeme@123";
string remoteAddress = "192.168.18.3"; // user IP address
string port = "vty0"; // user port

// Create the client
var client = new TacacsSharpClient(serverIP, serverPort, sharedKey);

// Authenticates an user using ASCII method
if(client.AuthenticateAscii(username, password, remoteAddress, port) == AuthenticationStatus.PASS)
{
    Console.WriteLine("May the force be with you...");
}
else
{
    Console.WriteLinte("YOU SHALL NOT PASS!");
}
```

### Functions Supported
- Version 1.0
  - Synchronous and Asynchronous authentication
