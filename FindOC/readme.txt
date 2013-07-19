Find Opcode
Copyright ® Mario Vilas (aka QvasiModo)
Version 1.00
Last updated 21 May 05

This program is released under the terms of the GNU Public License. Please
refer to "gpl.txt" for further details.

--------------------------------------oOo--------------------------------------

What is it?
-----------

This application was designed to aid security experts in writing proof of
concept code (exploits) while searching for bugs. It allows the user to look
for any given IA32 assembly instruction within a system library of choice, and
obtain the memory address for it.

If you don't know why you would want it, or how can it help you, then this
tool is probably not for you. ;)

--------------------------------------oOo--------------------------------------

How do I use it?
----------------



--------------------------------------oOo--------------------------------------

How do I recompile it?
----------------------

You will need the Pelle's C environment. The sources are divided into two
projects: "disasm" and "findoc", to be compiled in that order.

The first is the assembly/disassembly library written by ___, author of the
OllyDbg debugger. It will build a static library "disasm.lib" and place it in
the "..\findoc" folder.

The second project is for the main program itself. It'll build an executable
file in it's parent folder.

You can additionally compress the executable with UPX to reduce it's size.

--------------------------------------oOo--------------------------------------

Links, links, links...
----------------------

http://www.pellesc.org		The Pelle's C programming environment.
http://www.ollydbg.org		The OllyDbg debugger home page.
http://www.upx.org		The Ultimate Packer for eXecutables.

-------------------------------------[eOf]-------------------------------------
