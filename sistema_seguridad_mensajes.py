from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Variables globales para almacenar datos del sistema
mensaje_original = ""
hash_calculado = 0
mensaje_comprimido = ""
clave_privada = None
clave_publica = None
firma_digital = None
datos_enviados = {}
verificacion_realizada = False
mensaje_autentico = False


# Implementacion del algoritmo de hash FNV-1
def calcular_hash_fnv1(texto):
    FNV_PRIME = 16777619
    FNV_OFFSET = 2166136261

    hash_valor = FNV_OFFSET
    for byte in texto.encode("utf-8"):
        hash_valor = hash_valor * FNV_PRIME
        hash_valor = hash_valor ^ byte
        hash_valor = hash_valor & 0xFFFFFFFF  # Mantener 32 bits

    return hash_valor


# Compresion RLE (Run-Length Encoding)
def comprimir_rle(texto):
    if not texto:
        return ""

    comprimido = []
    i = 0

    while i < len(texto):
        caracter_actual = texto[i]
        contador = 1

        # Contar caracteres consecutivos iguales
        while (
            i + contador < len(texto)
            and texto[i + contador] == caracter_actual
            and contador < 9
        ):
            contador += 1

        # Agregar al resultado: numero + caracter
        comprimido.append(str(contador) + caracter_actual)
        i += contador

    return "".join(comprimido)


# Descompresion RLE
def descomprimir_rle(texto_comprimido):
    descomprimido = []
    i = 0

    while i < len(texto_comprimido):
        # Leer el numero
        if i < len(texto_comprimido) and texto_comprimido[i].isdigit():
            cantidad = int(texto_comprimido[i])
            i += 1

            # Leer el caracter
            if i < len(texto_comprimido):
                caracter = texto_comprimido[i]
                descomprimido.append(caracter * cantidad)
                i += 1
        else:
            i += 1

    return "".join(descomprimido)


# Generar par de claves RSA
def generar_claves_rsa():
    clave_priv = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    clave_pub = clave_priv.public_key()
    return clave_priv, clave_pub


# Firmar el hash usando la clave privada
def firmar_hash(hash_valor, clave_priv):
    # Convertir hash a bytes
    hash_bytes = hash_valor.to_bytes(4, byteorder="big")

    # Firmar usando la clave privada
    firma = clave_priv.sign(
        hash_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
    return firma


# Verificar firma usando la clave publica
def verificar_firma(hash_valor, firma, clave_pub):
    try:
        hash_bytes = hash_valor.to_bytes(4, byteorder="big")

        clave_pub.verify(
            firma,
            hash_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True
    except:
        return False


# Opcion 1: Ingresar mensaje
def ingresar_mensaje():
    global \
        mensaje_original, \
        hash_calculado, \
        mensaje_comprimido, \
        firma_digital, \
        datos_enviados, \
        verificacion_realizada

    print("\n" + "=" * 60)
    print("INGRESAR MENSAJE")
    print("=" * 60)

    mensaje_original = input("Ingrese el mensaje: ")

    # Reiniciar variables al ingresar nuevo mensaje
    hash_calculado = 0
    mensaje_comprimido = ""
    firma_digital = None
    datos_enviados = {}
    verificacion_realizada = False

    print(f"\nMensaje ingresado: '{mensaje_original}'")
    print(f"Longitud: {len(mensaje_original)} caracteres")


# Opcion 2: Calcular hash FNV-1
def calcular_hash():
    global mensaje_original, hash_calculado

    print("\n" + "=" * 60)
    print("CALCULAR HASH FNV-1")
    print("=" * 60)

    if not mensaje_original:
        print("ERROR: Primero debe ingresar un mensaje (opcion 1)")
        return

    hash_calculado = calcular_hash_fnv1(mensaje_original)

    print(f"Mensaje: '{mensaje_original}'")
    print(f"Hash FNV-1 calculado: {hash_calculado}")
    print(f"Hash en hexadecimal: 0x{hash_calculado:08X}")


# Opcion 3: Comprimir mensaje con RLE
def comprimir_mensaje():
    global mensaje_original, mensaje_comprimido

    print("\n" + "=" * 60)
    print("COMPRIMIR MENSAJE CON RLE")
    print("=" * 60)

    if not mensaje_original:
        print("ERROR: Primero debe ingresar un mensaje (opcion 1)")
        return

    tamaño_original = len(mensaje_original)
    mensaje_comprimido = comprimir_rle(mensaje_original)
    tamaño_comprimido = len(mensaje_comprimido)

    print(f"Mensaje original: '{mensaje_original}'")
    print(f"Tamaño original: {tamaño_original} caracteres")
    print(f"\nMensaje comprimido (RLE): '{mensaje_comprimido}'")
    print(f"Tamaño comprimido: {tamaño_comprimido} caracteres")

    if tamaño_comprimido < tamaño_original:
        ahorro = ((tamaño_original - tamaño_comprimido) / tamaño_original) * 100
        print(f"Compresion: {ahorro:.2f}% de ahorro")
    elif tamaño_comprimido > tamaño_original:
        aumento = ((tamaño_comprimido - tamaño_original) / tamaño_original) * 100
        print(
            f"Expansion: {aumento:.2f}% de aumento (RLE no es eficiente para este mensaje)"
        )
    else:
        print("Sin cambio en el tamaño")


# Opcion 4: Firmar el hash con RSA
def firmar_hash_mensaje():
    global hash_calculado, clave_privada, clave_publica, firma_digital

    print("\n" + "=" * 60)
    print("FIRMAR HASH CON RSA")
    print("=" * 60)

    if hash_calculado == 0:
        print("ERROR: Primero debe calcular el hash (opcion 2)")
        return

    print("Generando par de claves RSA...")
    clave_privada, clave_publica = generar_claves_rsa()
    print("Claves RSA generadas correctamente")

    print("\nFirmando el hash con la clave privada...")
    firma_digital = firmar_hash(hash_calculado, clave_privada)

    print(f"\nHash a firmar: {hash_calculado}")
    print(f"Firma digital generada (primeros 50 bytes): {firma_digital[:50].hex()}...")
    print(f"Longitud de la firma: {len(firma_digital)} bytes")

    # Mostrar informacion de las claves
    print("\n--- CLAVES RSA GENERADAS ---")
    print("Clave privada: [CONFIDENCIAL - No se muestra]")
    print("Clave publica: [Disponible para verificacion]")
    print("Tamaño de clave: 2048 bits")


# Opcion 5: Simular envio
def simular_envio():
    global mensaje_comprimido, firma_digital, clave_publica, datos_enviados

    print("\n" + "=" * 60)
    print("SIMULAR ENVIO")
    print("=" * 60)

    if not mensaje_comprimido:
        print("ERROR: Primero debe comprimir el mensaje (opcion 3)")
        return

    if firma_digital is None:
        print("ERROR: Primero debe firmar el hash (opcion 4)")
        return

    # Simular envio almacenando en diccionario
    datos_enviados = {
        "mensaje_comprimido": mensaje_comprimido,
        "firma": firma_digital,
        "clave_publica": clave_publica,
    }

    print("Simulando envio del paquete seguro...")
    print("\n--- DATOS TRANSMITIDOS ---")
    print(f"1. Mensaje comprimido (RLE): '{datos_enviados['mensaje_comprimido']}'")
    print(f"   Tamaño: {len(datos_enviados['mensaje_comprimido'])} caracteres")
    print(
        f"\n2. Firma digital (primeros 50 bytes): {datos_enviados['firma'][:50].hex()}..."
    )
    print(f"   Tamaño: {len(datos_enviados['firma'])} bytes")
    print("\n3. Clave publica: [Incluida para verificacion]")

    print("\n--- DATOS NO TRANSMITIDOS ---")
    print("Clave privada: [PERMANECE SECRETA EN EL EMISOR]")

    print("\nEnvio simulado exitosamente!")


# Opcion 6: Descomprimir y verificar firma
def descomprimir_y_verificar():
    global datos_enviados, verificacion_realizada, mensaje_autentico

    print("\n" + "=" * 60)
    print("RECEPCION Y VERIFICACION")
    print("=" * 60)

    if not datos_enviados:
        print("ERROR: No hay datos para recibir (primero ejecute opcion 5)")
        return

    print("Simulando recepcion del paquete...")
    print("\n--- PASO 1: DESCOMPRIMIR MENSAJE ---")
    mensaje_recibido_comprimido = datos_enviados["mensaje_comprimido"]
    mensaje_descomprimido = descomprimir_rle(mensaje_recibido_comprimido)

    print(f"Mensaje comprimido recibido: '{mensaje_recibido_comprimido}'")
    print(f"Mensaje descomprimido: '{mensaje_descomprimido}'")

    print("\n--- PASO 2: CALCULAR HASH DEL MENSAJE RECIBIDO ---")
    hash_recibido = calcular_hash_fnv1(mensaje_descomprimido)
    print(f"Hash FNV-1 calculado: {hash_recibido}")
    print(f"Hash en hexadecimal: 0x{hash_recibido:08X}")

    print("\n--- PASO 3: VERIFICAR FIRMA DIGITAL ---")
    firma_recibida = datos_enviados["firma"]
    clave_pub_recibida = datos_enviados["clave_publica"]

    print("Verificando firma con la clave publica...")
    es_valido = verificar_firma(hash_recibido, firma_recibida, clave_pub_recibida)

    verificacion_realizada = True
    mensaje_autentico = es_valido

    if es_valido:
        print("VERIFICACION: EXITOSA")
        print("La firma es valida para el hash calculado")
    else:
        print("VERIFICACION: FALLIDA")
        print("La firma NO coincide con el hash calculado")


# Opcion 7: Mostrar resultado de autenticacion
def mostrar_resultado():
    print("\n" + "=" * 60)
    print("RESULTADO DE AUTENTICACION")
    print("=" * 60)

    if not verificacion_realizada:
        print("ERROR: Primero debe realizar la verificacion (opcion 6)")
        return

    print("\n" + "*" * 60)
    if mensaje_autentico:
        print("*** MENSAJE AUTENTICO Y NO MODIFICADO ***")
        print("\nEl mensaje ha sido verificado correctamente:")
        print("- La firma digital es valida")
        print("- El mensaje no ha sido alterado")
        print("- La integridad del mensaje esta garantizada")
    else:
        print("*** MENSAJE ALTERADO O FIRMA NO VALIDA ***")
        print("\nADVERTENCIA: El mensaje NO es confiable:")
        print("- La firma digital no coincide")
        print("- El mensaje puede haber sido modificado")
        print("- La integridad del mensaje esta comprometida")
    print("*" * 60)


# Menu principal
def mostrar_menu():
    print("\n" + "=" * 60)
    print("SISTEMA DE MENSAJERIA SEGURA")
    print("FNV-1 + RLE + RSA")
    print("=" * 60)
    print("1. Ingresar mensaje")
    print("2. Calcular hash FNV-1")
    print("3. Comprimir mensaje (RLE)")
    print("4. Firmar el hash con clave privada RSA")
    print("5. Simular envio (Mensaje comprimido + Firma + Clave publica)")
    print("6. Descomprimir y verificar firma (Clave Publica)")
    print("7. Mostrar si el mensaje es autentico o alterado")
    print("8. Salir")
    print("=" * 60)


def main():
    while True:
        mostrar_menu()
        opcion = input("Seleccione una opcion: ")

        if opcion == "1":
            ingresar_mensaje()
        elif opcion == "2":
            calcular_hash()
        elif opcion == "3":
            comprimir_mensaje()
        elif opcion == "4":
            firmar_hash_mensaje()
        elif opcion == "5":
            simular_envio()
        elif opcion == "6":
            descomprimir_y_verificar()
        elif opcion == "7":
            mostrar_resultado()
        elif opcion == "8":
            print("\nSaliendo del sistema...")
            break
        else:
            print("\nOpcion no valida. Intente nuevamente.")

        input("\nPresione Enter para continuar...")


if __name__ == "__main__":
    main()
