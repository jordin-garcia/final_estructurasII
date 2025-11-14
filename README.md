# Sistema de Mensajería Segura
## FNV-1 Hash + RLE Compression + RSA Digital Signature

### Descripción
Aplicación de consola que implementa un sistema de mensajería segura utilizando:
- **Hash FNV-1**: Para generar un resumen del mensaje
- **RLE (Run-Length Encoding)**: Para comprimir el mensaje
- **RSA**: Para firma digital y verificación de autenticidad

### Requisitos
- Python 3.7 o superior
- Librería cryptography

### Instalación

1. Instalar las dependencias:
```bash
pip install -r requirements.txt
```

### Ejecución

```bash
python sistema_seguridad_mensajes.py
```

### Funcionalidades

El sistema ofrece un menú interactivo con las siguientes opciones:

1. **Ingresar mensaje**: Permite ingresar el texto que se desea enviar de forma segura
2. **Calcular hash FNV-1**: Genera un hash del mensaje usando el algoritmo FNV-1
3. **Comprimir mensaje (RLE)**: Comprime el mensaje usando Run-Length Encoding
4. **Firmar el hash con RSA**: Genera par de claves RSA y firma digitalmente el hash
5. **Simular envío**: Empaqueta mensaje comprimido + firma + clave pública
6. **Descomprimir y verificar**: Simula la recepción, descomprime y verifica la firma
7. **Mostrar resultado**: Indica si el mensaje es auténtico o ha sido alterado
8. **Salir**: Cierra el programa

### Flujo de Uso Típico

1. Seleccione opción 1 para ingresar un mensaje
2. Seleccione opción 2 para calcular el hash
3. Seleccione opción 3 para comprimir el mensaje
4. Seleccione opción 4 para generar claves y firmar
5. Seleccione opción 5 para simular el envío
6. Seleccione opción 6 para verificar en el receptor
7. Seleccione opción 7 para ver el resultado de autenticación

### Ejemplo de Uso

```
Mensaje: "AAABBBCCCC"
Hash FNV-1: Genera un número de 32 bits
Compresión RLE: "3A3B4C"
Firma RSA: Firma digital del hash
Verificación: Confirma autenticidad del mensaje
```

### Detalles Técnicos

- **FNV-1**: Implementación del algoritmo de hash de 32 bits
- **RLE**: Compresión básica contando caracteres consecutivos
- **RSA**: Claves de 2048 bits con padding PSS y SHA-256

### Seguridad

- La clave privada NUNCA se transmite
- Solo se envía: mensaje comprimido + firma + clave pública
- El receptor puede verificar la autenticidad sin conocer la clave privada

