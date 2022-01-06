import ssl
import requests

def get_ssl_context(ignore_cert_errors):
    ctx = ssl.create_default_context()
    ctx.set_ciphers('DEFAULT@SECLEVEL=1')
    
    if ignore_cert_errors:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    
    return ctx

class TLSAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, ignore_cert_errors):
        self.ignore_cert_errors = ignore_cert_errors
        super().__init__()
    
    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = get_ssl_context(self.ignore_cert_errors)
        return super(TLSAdapter, self).init_poolmanager(*args, **kwargs)