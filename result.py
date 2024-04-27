class Result:
    """
    A simple result class representing either a successful result (value) or an error.
    """

    def __init__(self, value=None, error=False, message=None):
        """
        Initializes a new Result object.

        :param value: The value of the result (if successful).
        :param error: The error code (if an error occurred).
        :param message: The error message (if an error occurred).
        """
        self.value = value
        self.error = error
        self.message = message

    def is_ok(self):
        """
        Checks if the result is a successful one.

        :return: True if the result is successful, False otherwise.
        """
        return not self.error 

    def is_err(self):
        """
        Checks if the result represents an error.

        :return: True if the result is an error, False otherwise.
        """
        return self.error 

    def unwrap(self):
        """
        Retrieves the value of the result if it's successful, otherwise raises an error.

        :return: The value of the result if successful.
        :raises ValueError: If the result represents an error.
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