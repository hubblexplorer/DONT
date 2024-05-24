class Result:
    """
    Representa uma classe simples para representar um resultado bem-sucedido (valor) ou um erro.
    """

    def __init__(self, value=None, error=False, message=None):
        """
        Inicia um novo objeto de Resultado.

        :param value: O valor do resultado (se bem-sucedido).
        :param error: Código de erro (se ocorreu um erro).
        :param message: A messagem de erro (se ocorreu um erro).
        """
        self.value = value
        self.error = error
        self.message = message

    def is_ok(self):
        """
        Verifica se o resultado representa uma operação bem-sucedida.

        :return: True se o resultado for bem-sucedido, False caso contrário.
        """
        return not self.error 

    def is_err(self):
        """
        Verifica se o resultado representa um erro.

        :return: True se o resultado for um erro, False caso contrário.
        """
        return self.error

    def unwrap(self):
        """
        Retorna o valor do resultado se ele for bem-sucedido, ou levanta uma exceção de ValueError.

        :return: O valor do resultado se ele for bem-sucedido.
        :raises ValueError: Se o resultado represente um erro.
        """
        if self.error:
            raise ValueError(self.message)
        return self.value
"""
EXEMPLO DE UTILIZAÇÃO
Exemplo de utilização da classe Result
Criar um objeto Result representando um resultado bem-sucedido

resultado_sucesso = Result(value=42)
print("O resultado_sucesso está OK?", resultado_sucesso.is_ok()) # Output: True
print("O resultado_sucesso é um erro?", resultado_sucesso.is_err()) # Output: False
print("Valor do resultado_sucesso:", resultado_sucesso.unwrap()) # Output: 42
Criar um objeto Result representando um erro

resultado_erro = Result(error=404, mensagem="Não encontrado")
print("O resultado_erro está OK?", resultado_erro.is_ok()) # Output: False
print("O resultado_erro é um erro?", resultado_erro.is_err()) # Output: True
try:
print("Valor do resultado_erro:", resultado_erro.unwrap()) # Isto irá lançar um ValueError
except ValueError as e:
print("Erro:", e) # Output: Erro: Não encontrado
"""