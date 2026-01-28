import hashlib
import random
import base64


def miller_rabin(n, k=10):
    """ Teste de primalidade de Miller-Rabin. """
    """ Parâmetros:
        - n: número primo;
        - k: número de iterações. """

    """ O teste de primalidade de Miller Rabin é um teste probabilítico que determina se um número
    'n' é um provável número primo ou um número composto. """

    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # Decompor 'n-1' na forma d*2^r, em que 'd' é ímpar.
    # Incrmenta-se 'r' e 'd' é dividido por 2
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)  # Definir um número aleatório 'a' tal que 2 < a < n - 2
        x = pow(a, d, n)  # Computar x = (a^d) mod n
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):  
            x = pow(x, 2, n)
            # Continuar o laço enquanto (x^2) mod n != n-1
            if x == n - 1:
                break
        else:
            return False
    return True

def gerar_primo(bits):
    """ Geração de um número primo de 'bits' bits com o uso do teste de primalidade de Miller-Rabin. (No caso, bits = 1024) """

    """ A função em questão executa um comando de repetição 'while' para gerar um número ímpar qualquer de 1024 bits 
    e testá-lo para aferir se ele é primo ou não, de acordo com o teste de primalidade de Miller-Rabin. """

    while True:
        prime_candidate = random.getrandbits(bits)  # Gerar número aleatório de 1024 bits
        prime_candidate |= (1 << (bits - 1)) | 1  # Assegurar que o número é ímpar
        if miller_rabin(prime_candidate):
            return prime_candidate  # Término do while para quando o primo for encontrado de acordo com o teste de primalidade

def gcd(a, b):
    """ Máximo Divisor Comum (MDC) """

    """ Usado para verificar se MDC(e, φ(n)) = 1 """

    while b != 0:
        a, b = b, a % b
    return a

def mod_inverso(e, phi):
    """ Cálculo do inverso modular usando o Algoritmo Euclides Estendido. """

    """ A função a seguir executa o algoritmo Euclides Estendido para o cálculo
    da variável 'd', componente essencial da 'chave privada' do sistema RSA. """


    d, x1, x2, y1 = 0, 0, 1, 1
    temp_phi = phi

    while e > 0:
        temp1, temp2 = divmod(temp_phi, e)
        temp_phi, e = e, temp2
        x = x2 - temp1 * x1
        y = d - temp1 * y1
        x2, x1 = x1, x
        d, y1 = y1, y

    if temp_phi == 1:
        return d + phi

def gerar_chaves(bits=1024):
    """ Gera chaves RSA com números primos de 1024 bits. """

    """ A função faz os gera as variáveis que compõem o RSA, sendo elas 'p', 'q', 'n', 'φ(n)', 'e' e 'd',
    fazendo o uso das funções previamente criadas. """

    p = gerar_primo(bits)  # Geração do número primo 'p' com 1024 bits
    q = gerar_primo(bits)  # Geração do número primo 'q' com 1024 bits
    print("p:", p, "\n")
    print("q:", q, "\n")
    n = p * q  # Cálculo de 'n'
    phi = (p - 1) * (q - 1)  # Cálculo de 'φ(n)'

    e = 65537  # Valor fixo de 'e'
    if gcd(e, phi) != 1: # Verificação se 'e' e 'φ(n)' são coprimos
        raise ValueError("Não foi possível encontrar valores válidos para as chaves.")

    d = mod_inverso(e, phi)  # Cálculo de 'd'
    return ((e, n), (d, n))  # Retorno das chaves pública e privada respectivamente

def mgf1(seed, mask_len, hash_function=hashlib.sha256):
    """ Mask Generation Function 1. """
    """ Parâmetros:
        - seed: valor inicial para ser usado na geração da máscara;
        - mask_len: tamanho da máscara para a máscara gerada em bytes;
        - hash_function: função hash a ser utilizada. No caso, foi a função SHA2 de 256 bytes. """
    
    """ Primitiva criptográfica similar a uma função hash criptográfica exceto pelo fato que a MGF suporta outputs 
    de tamanhos variados. """

    h_len = hash_function().digest_size  # Tamanho do valor de saída da função de hash SHA-256
    T = b''  # Inicialização de string de bytes como vazia que armazenará a máscara gerada
    for i in range(0, -(-mask_len // h_len)):
        C = i.to_bytes(4, byteorder='big')  # Representação em bytes do número 'i'
        T += hash_function(seed + C).digest()  # Concatenação da 'seed' com 'C'
    return T[:mask_len]

""" OAEP é um esquema de padding que processa o plaintext antes de realizar a encriptação/decriptação 
assimétrica. É uma técnica provada segura contra ataques de chosen-ciphertext. No presente código, o uso do OAEP 
é dividido para aplicação anterior à encriptação (oaep_encode) e anterior à decodificação (oaep_decode) 
do RSA. """

def oaep_encode(message, n, label=b"", hash_function=hashlib.sha256):
    """ Optimal Asymmetric Encryption Padding (Encode)."""
    """ Parâmetros:
        - message: mensagem a ser codificada;
        - n: módulo do RSA
        - label: rótulo;
        - hash_function: função hash a ser utilizada. No caso, foi a função SHA2 de 256 bytes. """


    k = (n.bit_length() + 7) // 8  # Tamanho do bloco em bytes
    m_len = len(message)  # Comprimento da mensagem
    h_len = hash_function().digest_size  # Tamanho do valor de saída da função de hash SHA-256
    ps_len = k - m_len - 2 * h_len - 2  # Comprimento do padding da string

    if ps_len < 0:
        raise ValueError("Mensagem muito longa.")

    l_hash = hash_function(label).digest()  # Hash do rótulo a ser usado como parte dos dados codificados
    ps = b'\x00' * ps_len  # String de bytes com comprimento 'ps_len'
    db = l_hash + ps + b'\x01' + message  # 'data block': é a estrutura dos dados codificados
    seed = random.randbytes(h_len)
    db_mask = mgf1(seed, k - h_len - 1, hash_function)  # Gerado ao ser aplicado ao MGF1
    masked_db = bytes(x ^ y for x, y in zip(db, db_mask))  # Aplicação de XOR byte a byte para gerar 'masked_db'
    seed_mask = mgf1(masked_db, h_len, hash_function)  # Gerado ao ser aplicado ao MGF1
    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask)) 
    em = b'\x00' + masked_seed + masked_db  # 'encoded message': mensagem codificada composta por 'masked_seed' e 'masked_db'
    return int.from_bytes(em, byteorder='big')  # Retorno da conversão de 'em' para um número inteiro com 'big-endian'

def oaep_decode(c, n, label=b"", hash_function=hashlib.sha256):
    """ Optimal Asymmetric Encryption Padding (Decode)."""
    """ Parâmetros:
        - c: mensagem a ser decodificada;
        - n: módulo do RSA;
        - label: rótulo;
        - hash_function: função hash a ser utilizada. No caso, foi a função SHA2 de 256 bytes. """

    k = (n.bit_length() + 7) // 8   # Tamanho do bloco em bytes
    h_len = hash_function().digest_size  # Tamanho do valor de saída da função de hash SHA-256

    c_bytes = c.to_bytes(k, byteorder='big')  # Conversão da mensagem codificada para um vetor de bytes
    l_hash = hash_function(label).digest()  # Hash do rótulo a ser usado como parte dos dados decodificadas

    masked_seed = c_bytes[1:h_len + 1]  # Extração do 'masked_seed' a partir de 'c_bytes'
    masked_db = c_bytes[h_len + 1:]  # Extração do 'masked_db' a partir de 'c_bytes'

    seed_mask = mgf1(masked_db, h_len, hash_function)    # Gerado ao ser aplicado ao MGF1
    seed = bytes(x ^ y for x, y in zip(masked_seed, seed_mask))
    db_mask = mgf1(seed, k - h_len - 1, hash_function)  # Gerado ao ser aplicado ao MGF1
    db = bytes(x ^ y for x, y in zip(masked_db, db_mask))  # 'data block': é a estrutura dos dados obtidas pelo XOR byte a byte entre 'masked_db' e 'db_mask'

    l_hash_prime = db[:h_len]
    if l_hash_prime != l_hash:
        raise ValueError("Hash do rótulo não corresponde.")

    db = db[h_len:]  # Remoção dos primeiros 'h_len' bytes de db
    i = db.index(b'\x01')
    mensagem = db[i + 1:]  # Extração da mensagem a partir de 'db'
    return mensagem

def dividir_mensagem_em_blocos(mensagem, block_size):
    """ Divide a mensagem em blocos menores compatíveis com o tamanho máximo permitido pelo OAEP. """
    """ Parâmetros:
        - mensagem: mensagem a ser dividida;
        - block_size: tamanho de cada bloco. """

    blocos = [mensagem[i:i + block_size] for i in range(0, len(mensagem), block_size)]
    return blocos

def encriptar(chave_publica, plaintext):
    """ Criptografar string usando a chave pública com OAEP. """
    """ Parâmetros:
        - chave_publica: conjunto (e, n) do RSA;
        - plaintext: texto a ser encriptado. """

    e, n = chave_publica
    k = (n.bit_length() + 7) // 8  # Tamanho do bloco em bytes
    h_len = hashlib.sha256().digest_size  # Tamanho do hash da função SHA-256
    max_block_size = k - 2 * h_len - 2  # Tamanho máximo de cada bloco

    blocos = dividir_mensagem_em_blocos(plaintext.encode('utf-8'), max_block_size)  # Dividir o plaintext em blocos com codificação UTF-8 compatíveis com OAEP
    ciphertext = [pow(oaep_encode(bloco, n), e, n) for bloco in blocos]  # Encriptar cada bloco de acordo com o RSA (C = M^e mod n), com o uso do OAEP
    return ciphertext

def decriptar(chave_privada, ciphertext):
    """ Descriptografar uma mensagem usando a chave privada com OAEP. """
    """ Parâmetros:
        - chave_privada: conjunto (d, n) do RSA;
        - ciphertext: texto a ser decriptado. """

    d, n = chave_privada
    plaintext = b''  # Inicialização da variável plaintext (string de bytes) vazia para armazenar o ciphertext a ser decodificado

    for bloco in ciphertext:
        decoded_block = pow(bloco, d, n)  # Decriptografar cada bloco de acordo com o RSA (M = C^d mod n)
        plaintext += oaep_decode(decoded_block, n)  # Decodificar o OAEP utilizado
    return plaintext.decode('utf-8')

def hash_message(mensagem):
    """ Calcular o hash da mensagem usando SHA-3. """

    hash_obj = hashlib.sha3_256()
    hash_obj.update(mensagem.encode('utf-8'))
    return hash_obj.digest()

def assinar_mensagem(chave_privada, mensagem):
    """ Assinar a mensagem (criptografa o hash da mensagem). """

    d, n = chave_privada
    mensagem_hash = hash_message(mensagem)  # Aplicar a mensagem na função de hash
    assinatura = pow(int.from_bytes(mensagem_hash, 'big'), d, n)  # Cálculo da assinatura
    return base64.b64encode(assinatura.to_bytes((assinatura.bit_length() + 7) // 8, 'big')).decode('utf-8')  # Codificação da assinatura para BASE64

def verificar_assinatura(chave_publica, mensagem, assinatura):
    """ Verificar a assinatura da mensagem. """

    e, n = chave_publica
    mensagem_hash = hash_message(mensagem)  # Aplicar a mensagem na função de hash
    signature_bytes = base64.b64decode(assinatura)  # Decodificar a mensagem na BASE64
    signature_int = int.from_bytes(signature_bytes, 'big')  # Conversão da assinatura para um número inteiro com 'big-endian'
    decoded_hash = pow(signature_int, e, n)  # Decodificar o hash
    return mensagem_hash == decoded_hash.to_bytes((decoded_hash.bit_length() + 7) // 8, 'big')  # Retorna 'True' quando a mensagem for igual
                                                                                               # ao hash decodificado, e 'False' caso contrário.

def parsing_documento_assinado(documento):
    """ Fazer o parsing do documento assinado e decifrar a mensagem e a assinatura. """

    parts = documento.split('||')  # O documento é uma string com a mensagem e a assinatura concatenadas com um separador
    if len(parts) != 2:
        raise ValueError("Formato do documento inválido.")
    encoded_message, encoded_signature = parts  # Atribuição de partes do 'documento' para tais variáveis
    mensagem = base64.b64decode(encoded_message).decode('utf-8')  # Decodificar a mensagem na BASE64
    assinatura = encoded_signature
    return mensagem, assinatura

def ler_arquivo(arquivo):
    """ Extrair os dados do plaintext a partir de um arquivo .txt."""

    with open(arquivo, 'r', encoding = 'utf-8') as file:
        return file.read()


if __name__ == "__main__":
    print("Geração de chaves de 1024 bits com verificação de primalidade de Miller-Rabin:\n")
    public_key, private_key = gerar_chaves(1024)

    arquivo = "lyrics.txt"   # Arquivo .txt a ser utilizado no código
    mensagem = ler_arquivo(arquivo)
    print("\nMensagem original:\n\n", mensagem)

    # Criptografar
    ciphertext = encriptar(public_key, mensagem)
    # Concatenar elementos de ciphertext para imprimir
    ciphertext_cc = ''.join(str(i) for i in ciphertext)
    print("\nMensagem criptografada:", ciphertext_cc)

    # Descriptografar
    decrypted_message = decriptar(private_key, ciphertext)
    print("\nMensagem descriptografada:", decrypted_message)

    # Assinar a mensagem
    assinatura = assinar_mensagem(private_key, mensagem)
    print("\nAssinatura da mensagem:", assinatura)

    # Verificar a assinatura
    is_valid = verificar_assinatura(public_key, mensagem, assinatura)
    print("\nA assinatura é válida?", is_valid)

    # Formatar documento assinado
    encoded_message = base64.b64encode(mensagem.encode('utf-8')).decode('utf-8')
    signed_document = f"{encoded_message}||{assinatura}"
    print("\nMensagem assinada:", signed_document)

    # Parsing do documento assinado
    parsed_message, parsed_signature = parsing_documento_assinado(signed_document)
    print("\nMensagem parseada:\n\n", parsed_message)
    print("Assinatura parseada:", parsed_signature)

    # Verificar a assinatura parseada
    is_valid_parsed = verificar_assinatura(public_key, parsed_message, parsed_signature)
    print("\nA assinatura parseada é válida?", is_valid_parsed)