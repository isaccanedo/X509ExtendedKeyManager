# X509ExtendedKeyManager
:fish: Este exemplo mostra o código inteiro para um KeyManager personalizado que estende X509ExtendedKeyManager. A maioria dos métodos simplesmente retorna o valor retornado da classe KeyManager que está sendo encapsulada por esta classe MyX509ExtendedKeyManager. No entanto, o método chooseServerAlias chama getHandshakeApplicationProtocol no objeto SSLSocket e, portanto, pode determinar o valor ALPN negociado atual
