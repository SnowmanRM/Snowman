class InvalidValueError(Exception):
    """Exception thrown if an invalid value is encountered.
    Example: checking if A.type == "type1" || A.type == "type2"
    A.type is actually "type3" which is not expected => throw this exception. 
    Throw with custom message: InvalidValueError("I did not expect that value!")"""
    
    def __init__(self, message):
        Exception.__init__(self, message)