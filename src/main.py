from verifier import Verifier
from wallet import Wallet


wallet = Wallet(1)
verifier = Verifier(13374, 2)
verifier.start()
wallet.start()
