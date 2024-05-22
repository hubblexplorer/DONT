class Result:
    """
    Representa uma classe simples para representar um resultado bem-sucedido (valor) ou um erro.
    """

    def __init__(self, value=None, error=False, message=None):
        """
        Inicializa uma nova objeto de Resultado.

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
EXAMPLE OF USAGE

# Example usage of the Result class

# Create a Result object representing a successful result
success_result = Result(value=42)
print("Is success_result OK?", success_result.is_ok())  # Output: True
print("Is success_result an error?", success_result.is_err())  # Output: False
print("Success result value:", success_result.unwrap())  # Output: 42

# Create a Result object representing an error
error_result = Result(error=404, message="Not found")
print("Is error_result OK?", error_result.is_ok())  # Output: False
print("Is error_result an error?", error_result.is_err())  # Output: True
try:
    print("Error result value:", error_result.unwrap())  # This will raise a ValueError
except ValueError as e:
    print("Error:", e)  # Output: Error: Not found

"""