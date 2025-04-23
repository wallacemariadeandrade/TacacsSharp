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

// Authorize an user actions
var author = client.Authorize(username, new[] {"service=shell", "cmd="});
if (author.Status == AuthorizationStatus.TAC_PLUS_AUTHOR_STATUS_PASS_ADD || author.Status == AuthorizationStatus.TAC_PLUS_AUTHOR_STATUS_PASS_REPL)
{
	Console.WriteLine("You are authorized to do {author.Args}");
}
else
{
	Console.WriteLine("You are not authorized to do {author.Args}");
}

// Account an user actions
var acct = client.Accounting(username);
if (acct.Status == AccountingStatus.TAC_PLUS_ACCT_STATUS_SUCCESS)
{
	Console.WriteLine("Your acctions list: {acct.Data}");
}
else
{
	Console.WriteLine("There is an error");
}
```

### Functions Supported
- Version 2.0
  - Authorization and Accounting
- Version 1.0
  - Synchronous and Asynchronous authentication
