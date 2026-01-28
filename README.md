# Descrição

O código em questão se refere à implementação de um gerador e verificador de assinaturas RSA em arquivos usando *Python (versão 3.12.7)*. O sistema criptográfico RSA é de chave assimétrica, utilizando chaves pública $(e, n)$ e privada $(d, n)$.

# Geração e Cifra de Chaves (RSA com OAEP)

- **Geração de Chaves:** A função `gerar_primos` gera números primos $p$ e $q$ de 1024 bits, utilizando o Teste de Primalidade de Miller-Rabin. O $n$ é o produto de $p$ e $q$. Além disso, calcula-se a **função totiente de Euler** a partir da fórmula: $\varphi(n)=(p-1)\times(q-1)$.
- **Chaves Pública e Privada:** A chave pública $e$ é fixada em 65537, e a chave privada $d$ é o inverso modular de $e$ em módulo $\varphi(n)$, calculado com o algoritmo de Euclides Estendido.
- **Encriptação com OAEP:** Para maior segurança, o algoritmo Optimal Asymmetric Encryption Padding (OAEP) é utilizado. A mensagem é dividida em blocos e processada pelo OAEP (que utiliza _padding_, valor inicial aleatório e máscaras MGF1) antes de ser encriptada com o RSA.
- **Decodificação com OAEP:** A decriptação é feita aplicando o RSA, seguido pela função `oaep_decode` para remover as máscaras e reconstruir a mensagem original.

# Assinatura e Verificação

- **Assinatura:** A função de _hash_ criptográfica SHA3-256 é aplicada à mensagem. O _hash_ é assinado usando a chave privada $(d, n)$ do RSA (exponenciação modular), e o resultado é formatado em BASE64.
- **Verificação:**
    1. A assinatura é decodificada de BASE64 e processada com a chave pública $(e, n)$ do RSA para recuperar o _hash_ original assinado.
    2. O _hash_ da mensagem em claro é calculado com SHA3-256.
    3. Os dois _hashes_ são comparados: se forem iguais, a assinatura é válida (retorna _True_).



