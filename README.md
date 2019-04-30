# keyring

KeyRing was written to make key derivation functions (keying) more approachable and easier to quickly develop during pentesting and red team operations. Keying is the idea of encrypting your original payload with local and remote resources, so it will only decrypt on the target system or under other situations.

This tool was developed to easily provide encryption/decryption code and other techniques for keying. The tool will output raw C#, JScript, or PowerShell that you can then build into your stage0/launcher payloads (e.g. MSBuild.exe). It should be expected that the raw output from these tools can and will be easily signatured. I find value in tools that don't do too much and give you the basics to allow for you to be creative when crafting your payloads.

### Compiled Binaries
You can retrieve the latest release of keyring binaries in the Releases page.

### Build
If you would prefer to build the source yourself, make sure Go 1.10+ is
installed and execute the following:

```
go get -u github.com/leoloobeek/keyring
```

### Usage
Head on over to the wiki for more usage information.

The [Walkthrough:Jscript](https://github.com/leoloobeek/keyring/wiki/Walkthrough:-JScript) page provides a full walkthrough, from beginning to end and is recommended to get started.

### Contributions
I'm sure there will definitely be bugs, but also this tool was written to match my workflow. If there's something you would find useful feel free to submit an Issue or even a PR!

### HUGE Thanks
[Josh Pitts](https://twitter.com/midnite_runr) and [Travis Morrow](https://twitter.com/wired33) came up with the first practical use case of environmental keying with their [Genetic Malware presentation](https://www.youtube.com/watch?v=WI8Y24jTTlw). They then released [Ebowla](https://github.com/Genetic-Malware/Ebowla), which is a fantastic project and does a lot more than this one, such as OTP. This project would never have been possible without Josh, Travis, and Ebowla.

Also thanks to the following:
- James Forshaw [@tiraniddo](https://twitter.com/tiraniddo) as I took some code from https://github.com/tyranid/DotNetToJScript/
- Will Schroeder [@harmj0y](https://twitter.com/harmj0y) and whoever else wrote the Empire PowerShell agent code
- Alex Rymdeko-harvey [@Killswitch_GUI](https://twitter.com/Killswitch_GUI) and Chris Truncer [@christruncer](https://twitter.com/christruncer) for [HttpKey](https://cybersyndicates.com/2015/06/veil-evasion-aes-encrypted-httpkey-request-module/) idea
