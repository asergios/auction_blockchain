# Check if a int port number is valid
# Valid is bigger than base port number
def check_port(port, base=1024):
    ivalue = int(port)
    if ivalue <= base:
        raise argparse.ArgumentTypeError("%s is an invalid positive int value" % value)
    return ivalue

# Load raw file from disk
# Used to load the keys pairs from the disk
def load_file_raw(path):
    with open(path, 'rb') as f: content = f.read()
    return content

# classe para gerir as ligações dos multiplos clientes
class OpenConnections:
    def __init__(self):
        self.nonce = os.urandom(16)
        self.openConns = {}

    def add(self, data):
        self.openConns[self.nonce] = (data)
        rv = self.nonce
        self.nonce = os.urandom(16)
        return rv

    def value(self, key):
    	return self.openConns.get(key, None)

    def pop(self, nonce):
        return self.openConns.pop(nonce, None)