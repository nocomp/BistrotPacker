simmple but effective shellcode loader in python, with injection.
Simply run:
python3 bistrotpacker -i shellcode.bin -o loader.cpp -p process-to-use.exe -s 5000 -k your_secret_key

then compile with:
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /TP loader.cpp /link /OUT:loader.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
