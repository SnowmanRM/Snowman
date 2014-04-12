class BadFormatError(Exception):
    """Exception thrown if an input file/line/string is badly formatted.
    Throw with custom message: BadFormatError("badly formatted file/line/string!")"""
    
    def __init__(self, message):
        Exception.__init__(self, message)
        
class AbnormalRuleError(Exception):
    """Exception thrown if an abnormal rule was encountered during parsing.
    An abnormal rule is a rule that is not part of the standard rules, e.g. 
    preproc_rules or so_rules. These rules are usually detected by looking for
    a gid-attribute which normal rules do not contain."""
    
    def __init__(self):
        Exception.__init__(self, "Abnormal rule encountered")        