"""
Google Credentials serialization helpers.

This is to assist gcsfs in serializing Credentials objects, which can sometimes
have unpicklable objects.
"""
import io
import pickle

__all__ = ["serialize", "deserialize"]


def _serialize_rsa_private_key(rsa_private_key):
    """
    This is required for Credential objects using the `google.auth.credentials.Signed`
    interface, which holds an instance of `google.auth.crypt.RSASigner`.
    For proper serialization, we need to handle de/serializing cryptography primitives
    from the `cryptography` package that are used in RSASigner.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKeyWithSerialization
        from cryptography.hazmat.primitives import serialization

        if not isinstance(rsa_private_key, RSAPrivateKeyWithSerialization):
            # if not a serializable RSA key, then we're not serializing
            raise NotImplementedError
        
        return rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            # WARNING! by not encrypting, we're sending private keys in plaintext!
            encryption_algorithm=serialization.NoEncryption()
        )
    except ImportError:
        # if unable to import cryptography, then we're not serializing
         raise NotImplementedError
    
def _deserialize_rsa_private_key(pem_key):
    """
    This is required for Credential objects using the `google.auth.credentials.Signed`
    interface, which holds an instance of `google.auth.crypt.RSASigner`.
    For proper serialization, we need to handle de/serializing cryptography primitives
    from the `cryptography` package that are used in RSASigner.
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from google.auth.crypt import _cryptography_rsa
        
        return serialization.load_pem_private_key(
            pem_key,
            password=None,
            # use Google auth library's suggested backend
            backend=_cryptography_rsa._BACKEND
        )
    except ImportError:
        # if unable to import cryptography, then we're not serializing
         raise NotImplementedError

class CredentialsPickler(pickle.Pickler):
    """ Custom credentials pickler.

    Uses the persistent_id method to serialize certain unserializable objects in
    a Credentials object.
    """
    def persistent_id(self, obj):
        try:
            # try to serialize object as if an RSAPrivateKeyWithSerialization
            pem_key = _serialize_rsa_private_key(obj)
            return ("RSAPrivateKeyWithSerialization", pem_key)
        except NotImplementedError:
            return None

class CredentialsUnpickler(pickle.Unpickler):
    """ Custom credentials unpickler.

    Uses the persistent_load method to deserialize certain unserializable objects in
    a Credentials object.
    """
    def persistent_load(self, serialized):
        type_tag, pem_key = serialized
        if type_tag == "RSAPrivateKeyWithSerialization":
            try:
                _deserialize_rsa_private_key(pem_key)
            except NotImplementedError:
                msg = "Unable to deserialize: {}".format(str(type_tag))
                raise pickle.UnpicklingError(msg)
        else:
            raise pickle.UnpicklingError("Unsupported persistent object.")

def serialize(credentials):
    """ Serialization method for Google Credentials

    Parameters
    ----------
    credentials : `google.auth.credentials.Credentials`
        The credentails to serialize

    Returns
    -------
    Pickled credential object

    Raises
    ------
    NotImplementedError
        If credentials aren't supported by serialize()
    """
    try:
        f = io.BytesIO()
        CredentialsPickler(f).dump(credentials)
        return f.getvalue()
    except pickle.PickleError:
        raise NotImplementedError

def deserialize(serialized_cred):
    """ De-serialization method for Google Credentials

    Parameters
    ----------
    serialized_cred : bytes
        Pickled credentials to deserialize

    Returns
    -------
    An instance of `google.auth.credentials.Credentials`

    Raises
    ------
    `pickle.UnpicklingError`
        If unpickling fails
    """
    f = io.BytesIO(serialized_cred)
    return CredentialsUnpickler(f).load()
