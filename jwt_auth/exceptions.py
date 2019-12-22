class Error(Exception):
    """Base class for other exceptions"""
    pass


class MissingPrivateKey(Error):
    """No rsa private key is defined in settings"""
    pass


class MissingPublicKey(Error):
    """No rsa public key is defined in settings"""
    pass
