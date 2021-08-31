# Liquid Snake

Liquid Snake is a program aimed at performing lateral movement against Windows systems without touching the disk.
The tool relies on WMI Event Subscription in order to execute a .NET assembly in memory, the .NET assembly will listen for a shellcode on a named pipe and then execute it using a variation of the thread hijacking shellcode injection.

## Credits 

- [MDSec - WMI Event Subscription](https://www.mdsec.co.uk/2020/09/i-like-to-move-it-windows-lateral-movement-part-1-wmi-event-subscription/)
- [pwndizzle - thread-hijack.cs](https://github.com/pwndizzle/c-sharp-memory-injection/blob/master/thread-hijack.cs)


## Intro 