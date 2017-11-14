# $DEC0DE

Remove encryption systems used to protect Atari ST programs.

Supported protections are:
- NTM/Cameo Toxic Packer v1.0
- R.AL Little Protection v01 & Megaprot v0.02
- Orion Sly Packer v2.0
- Cameo Cooper v0.5 & v0.6
- Illegal Anti-bitos v1.0, v1.4, v1.6 & v1.61
- Zippy Little Protection v2.05 & v2.06
- Yoda Lock-o-matic v1.3
- CID Encrypter v1.0bp
- Rob Northen Copylock Protection System series 1 (1988) & series 2 (1989)

The *prebuilt/* directory provides prebuilt binaries for Linux, Mac OS X, Windows and Atari ST.

The *samples/* directory provides protected programs samples.
See the *samples/README.txt* file for detailed information.

The *src/* directory provides the *dec0de.c* source file.

The source file can be compiled on any Operating System supporting gcc.
For non-Linux systems, the following gcc ports are available:
- gcc for Mac OS X  
  https://github.com/kennethreitz/osx-gcc-installer
- gcc for Windows  
  http://www.mingw.org
- gcc for Atari  
  http://vincent.riviere.free.fr/soft/m68k-atari-mint

Depending on the target Operating System, run gcc as follows:
- Linux  
  `$ gcc -O -Wall -Wextra -m32 -static dec0de.c -o dec0de`
- Mac OS X  
  `$ gcc -O -Wall -Wextra -mmacosx-version-min=10.5 dec0de.c -o dec0de`
- Windows  
  `$ gcc -O -Wall -Wextra -std=c99 dec0de.c -o dec0de.exe`
- Atari ST  
  `$ m68k-atari-mint-gcc -O -Wall -Wextra dec0de.c -o dec0de.prg`  
  or  
  `$ m68k-atari-mint-gcc -O -Wall -Wextra dec0de.c -o dec0de.ttp`

On Linux, Mac or Windows, run the *dec0de* program from the command prompt.  
To obtain usage information, run the program as follows:  
`$ dec0de -h`

On Atari ST, launch *dec0de.prg* or *dec0de.ttp* from the GEM desktop.  
*dec0de.prg* provides an interactive mode, while *dec0de.ttp* expects
parameters to be provided through the command line.
