# Vulnerable Server

> **CAUTION:** Don't use the compiled smart_server.c on a production server or on your own machine. It's recommended to use a virtual machine instead. Using it on a production server or on the own machine brings a risk to the whole operating system, because the existing hole could be exploited and a shellcode could be injected to the system by a thrid person (e.g. a hacker).

The SmartServer is a simple socket server that can be used to getting basic knowledge how buffer overflows works and what can be done with the resulting access through the hole.

## Buffer Overflows
Writing data to a buffer in a program, where the data size is greather than the size of the buffer, leads to buffer overflow. The data that overflows, overwrites content of the memory at that location. It is neccessary to check that the size of data isn't greather than the buffer size, before writing data into the buffer. Otherwhise shellcode could be injected into the system and for example a backdoor could be opened on the victim for the hacker. This project shows up one most common security hole in a program, that can be used to inject shellcode through a buffer overflow.

### Stack and the registers
To understand how the buffer overflow works it is necessary to get some basic knowledge about the stack, the registers and some of the pointers of modern processors. 
![](https://upload.wikimedia.org/wikipedia/commons/thumb/8/8a/ProgramCallStack2_en.png/800px-ProgramCallStack2_en.png)

## Tools


### Kali Linux


### Metasploit


## Buffer Overflow in the smart_server
![](images/001_compile_and_start.png)
![](images/002_test_with_netcat.png)

### Denial-of-Service-Attack
![](images/003_long_input.png)

### Bypass survey
![](images/004_run_server_debug.png)
![](images/005_check_stack.png)

### Reverse-TCP-Connection through shellcode injection
![](images/006_pattern_create.png)
![](images/007_segmentation_fault.png)
![](images/008_pattern_offset.png)
![](images/009_send_unique_pattern.png)
![](images/010_get_adress_of_shellcode.png)
![](images/011_generate_shellcode.png)
![](images/012_msfconsole.png)
![](images/013_run_exploit.png)
![](images/014_meterpreter.png)
