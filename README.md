# $DEC0DE

Remove encryption systems used to protect GEMDOS programs.

The *prebuilt/* directory provides prebuilt binaries for Linux, Mac OS X, Windows and Atari ST.

The *src/* directory provides the *dec0de.c* source file.

This source file can be compiled on any Operating System supporting gcc.  
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
