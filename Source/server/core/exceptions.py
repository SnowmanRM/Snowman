class MissingObjectError(Exception):
    """Exception thrown if a vital database object, such as 'all sensors' does not
    exist."""
    
    def __init__(self, message):
        Exception.__init__(self, message)