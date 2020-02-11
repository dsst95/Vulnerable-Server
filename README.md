# Vulnerable Server

> **CAUTION:** Don't use the compiled smart_server.c on a production server or on your own machine. It's recommended to use a virtual machine instead. Using it on a production server or on the own machine brings a risk to the whole operating system, because the existing hole could be exploited and a shellcode could be injected to the system by a thrid person (e.g. a hacker).

The SmartServer is a simple socket server that can be used to getting basic knowledge how buffer overflows works and what can be done with the resulting access through the hole.

## Buffer Overflows
Writing data to a buffer in a program, where the data size is greather than the size of the buffer, leads to buffer overflow. The data that overflows, overwrites content of the memory at that location. It is neccessary to check that the size of data isn't greather than the buffer size, before writing data into the buffer. Otherwhise shellcode could be injected into the system and for example a backdoor could be opened on the victim for the hacker. This project shows up one most common security hole in a program, that can be used to inject shellcode through a buffer overflow. To get more knowledge about the buffer overflow you can see [here](https://insecure.org/stf/smashstack.html).

## Buffer Overflow in the smart_server
First of all this exploit was only executed as a 32-Bit program, because 64-Bit has a longer address space and it is more complex to get the exploit run there. This server was only tested on a linux operating system, because on windows the GNU compiler and debugger may not work and other tools will be neccessary.

Before the exploit can be executed the server must be compiled with the following command. The param `-m32` means that the porgram gets compiled as a 32-Bit program, `-g` enables debugging for the compiled program. In modern operating systems there are security features like stack protection, not executeable stack and address space layout randomization (ASLR). To disable the ASLR a flag on the kernel must be set with the following command (a reboot may be neccessary):
```bash
echo 0 > /proc/sys/kernel/randomize_va_space
```
The stack protector gets disabled with the param `-fno-stack-protector` and the stack gets executeable with the param `-z exec-stack`. It may be possible to get the server exploited with enabled security features but to get only the basic knowledge about buffer overflows the security features were disabled. This is another reason to run the server only on a virtual machine and not on a real, accessable form the internet, server. After compiling the program to the outputfile specified with the `-o` flag, it can be started by executing the file and passing the port number on which the socket should listen.

![](images/001_compile_and_start.png)

To test the server with the correct inputs netcat can be used as follows:

![](images/002_test_with_netcat.png)

### Denial-of-Service-Attack
The first try is to send a big input to the server and check what will be the result. In the follwing example a python generated string containing 5000 A's is send to the server via netcat. The result will be after executing the command a not reachable server, caused by a segmentation fault. This is a successfull denial-of-service-attack, which has the target to overload a server, so that only few or no more requests can be handled. Also the error gives a hint for a possible buffer overflow, because in this case the memory address of the next command gets overwritten and if the new content doesn't represent a correct memory address a segmentation fault will be the result.

![](images/003_long_input.png)

### Bypass survey
The next possibility is to get with a buffer overflow access to the image form the server without knowing the correct secret text. With the GNU-Debugger `gdb` the program can be debugged and reverse engineered. The `list` command prints the decompiled source code. When using it you can find out, that in the method `checkAuth` a flag is set if the correct secret text gets passed by the user. Also you can see that the variable gets declared right after the `secret_buffer`. This means that a overflow of the `secret_buffer` array leads to a change of the flag used to indicate whether the passed secret text is correct or not. To check that a break point can be set right before the leaving the `checkAuth` function and the server can be started.

![](images/004_run_server_debug.png)

With the `list` function also can be find out, that the `secret_buffer` only has a size of 42 Bytes. So passing a string with a size of 43 chars could lead to getting the image form the server without knowing the correct secret text. After sending the secret text from the client the server will stop at the set breakpoint and the content of the variables can be printed out as follows:

![](images/005_check_stack.png)

Sending a string with 43 chars and the last char as thruthy value (e.g. 1), will lead to accessing the image without knowing the correct secret text by a buffer overflow into the `auth_flag`.

### Reverse-TCP-Connection through shellcode injection
Another possibility is to inject shellcode into the server with a buffer overflow and get access to the machine. The idea of that exploit is to inject executeable shell code trough a buffer overflow and overwrite the pointer to the address of the next command with the address of the injected shellcode. First of all the position in the stack which contains the address of the next command must be detected. One possibility is to send requests with a rising to the server and check if the string leads to a segmentation fault by a buffer overflow. Another possibility is to use the `msf-pattern_create` tool which creates a unique pattern, that allows to locate the position of the string where the address of the shellcode should be passed. With the `-l` parameter the lenght of uniqe string can be specified.

![](images/006_pattern_create.png)

Sending that long generated string leads to a segmentation fault.

![](images/007_segmentation_fault.png)

Passing the wrong address which caused the segmentation fault to `msf-pattern_offset` with the length of the generated pattern string, will return the offset in the string where the address to the shellcode should be passed.

![](images/008_pattern_offset.png)

To determine the address where the shellcode starts a unique pattern with the chars `A`, `B` and `C` can be used. Here it may be usefull to unset the environment variables on the victim server by calling `unset env` before starting the server in debug mode with the GNU-Debugger. This is neccessary to ensure that the address doesn't depent on environment variables, because they can differ between different victims. The first part contains a string with the char `A` with the length of the offset. Then `B` follows 4 times (32-Bit address equals to 4 Bytes). The last part of the string consists of some `C` (in this example 200).

![](images/009_send_unique_pattern.png)

After reaching the set breakpoint and printing out the content of `secret_buffer` in hex mode. The address of the first `C` which equals to the 0x43 (the content is from right to left in each block) equals to the address where the overwritten address should point to. In this case it is the address `0xffffcd50`.

![](images/010_get_adress_of_shellcode.png)

As the last step the shellcode, that should be injected by the buffer overflow, must be generated. For generating the shellcode the tool `msfvenom` of metasploit can be used which is installed per default on kali linux. In the following example a revserse tcp connection gets opened to the hacker system on port `5555` where the hacker will listen on. The param `PerpendSetuid` will call `setuid(0)` at the beginning, what leads to root rights independent from the user by which the proccess of the victim server runs. Also the param `-b '\x00'` must be set which removes bad chars, that terminates the string and the shellcode would be incomplete.

![](images/011_generate_shellcode.png)

Because the stack on each server can be different, caused by different environment variables it is neccessary to add a NOP-Slide. This contains NOP (no operation codes) which represented by the Byte `\x90` and the proccessor does nothing than sliding over the commands to the next executeable command. This makes it possible to set a address, that it is not hundred percent the address of the beginning of the shellcode but it is a guess of the middle of the NOP-Slide. The full exploit can be found in [exploit_smart_server.py](exploit_smart_server.py).

To test the exploit first of all on the hacker system (in this case kali linux) the metasploit console must be started and a listener for the reverse connection must be opened.

![](images/012_msfconsole.png)

As the next step the completed exploit should be run to inject the shellcode by a buffer overflow into the victim and get a reverse tcp connection opened.

![](images/013_run_exploit.png)

After injecting the shellcode into the victim the hacker will get access through meterpreter and can execute the desired commands on the hacked system.

![](images/014_meterpreter.png)
