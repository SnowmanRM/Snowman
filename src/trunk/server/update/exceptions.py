class BadFormatError(Exception):
    """Exception thrown if an input file/line/string is badly formatted.
    Throw with custom message: BadFormatError("badly formatted file/line/string!")"""
    
    def __init__(self, message):
        Exception.__init__(self, message)