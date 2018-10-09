# keyring

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

### Contributions
I'm sure there will definitely be bugs, but also this tool was written to match my workflow. If there's something you would find useful feel free to submit an Issue or even a PR!

### HUGE Thanks
[Josh Pitts](https://twitter.com/midnite_runr) and [Travis Morrow](https://twitter.com/wired33) came up with the first practical use case of environmental keying with their [Genetic Malware presentation](https://www.youtube.com/watch?v=WI8Y24jTTlw). They then released [Ebowla](https://github.com/Genetic-Malware/Ebowla), which is a fantastic project and does a lot more than this one, such as OTP. This project would never have been possible without Josh, Travis, and Ebowla.

Also thanks to the following:
- James Forshaw [@tiraniddo](https://twitter.com/tiraniddo) as I took some code from https://github.com/tyranid/DotNetToJScript/
- Will Schroeder [@harmj0y](https://twitter.com/harmj0y) and whoever else wrote the Empire PowerShell agent code
- Alex Rymdeko-harvey [@Killswitch_GUI](https://twitter.com/Killswitch_GUI) and Chris Truncer [@christruncer](https://twitter.com/christruncer) for [HttpKey](https://cybersyndicates.com/2015/06/veil-evasion-aes-encrypted-httpkey-request-module/) idea
