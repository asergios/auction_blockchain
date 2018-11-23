from ..common.certmanager import CertManager
f = open('./security2018-p1g1/auction_manager/keys/manager.crt', 'rb')
cert_text = f.read()
p = open('./security2018-p1g1/auction_manager/keys/private_key.pem', 'rb')
priv_key = p.read()

cm = CertManager(cert=cert_text, priv_key = priv_key)

sign = cm.sign("tomatoes")
print(sign)
print(cm.verify_signature(sign, "tomatoes"))
