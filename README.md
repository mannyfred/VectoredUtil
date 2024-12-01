# VectoredUtil

Useful for vectored handler debugging and other shenanigans

- Enumerate all VEH/VCH in running processes and view where they are located (image/memory)

  ![image](https://github.com/user-attachments/assets/93c93ccf-fc8f-4171-abf9-f57afbcd60d8)



- Displays memory permissions etc when a handler is pointing towards unbacked memory or a modified KnownDll

  ![image](https://github.com/user-attachments/assets/963ba9bd-d0e0-4f85-9a9f-e81eafd1f65f)


  
- Dump all VEH/VCH in a specific process, specify the amount of bytes to dump

  ![image](https://github.com/user-attachments/assets/9cbb0549-903e-4aba-9d36-37c0db12c53f)



- Overwrite a specific VEH/VCH in a specific process with a pointer to shellcode or other random pointer, useful when dealing with VEH(s) related to anti-debug
  ```
  .\VectoredUtil.exe -proc 12345 -overwrite veh 1 0x00007fffd255e1c4
  .\VectoredUtil.exe -debug -proc 12333 -overwrite vch 1 C:\payload.bin
  ```

  
- Inject a VEH/VCH into a process if there isn't one registered

  ![image](https://github.com/user-attachments/assets/23722b80-029b-4fd6-be7b-514aefbb2c74)


