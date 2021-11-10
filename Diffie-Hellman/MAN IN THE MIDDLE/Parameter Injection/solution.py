p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 0x02 
A = 0xa6874a5cdcfb0af86d227826d6c331b51c68fb0caffdbbfb4bd2f9977166668cab15838dcf8a065857eda7b798b30acad41fafff242af8051416dfb70a7662235179215802587c8267eb6605e51598069fba9eb26ae2a6d77326eac2ad9b7f53e80db3a0a6dbe0f9be61d9f87158085cf5b0e87ddcea88d880fbea5d0868dbe500471aa3f6ff9540c42700e725230302c3b9faf262d5f5761feffc2ad1e55ac83a0100a9b4d88c0dcbe40b7b9fe2e99a5e6b1a43f1920e27fb6c42fd5d37cdd3
B = 0xb53ef21117ee1938a00d2639e14c487c8dbb95694f973e2dc1608a058e474b03729af5fbc193cc3a03dd54daf8c7d1475e16e90addcd0a4cec9987fbb8211768ce85a5d192e7374e87b7f0e63315a70144b0745d2405d154d7d5941ab19265d6fdd45f0f2ea5286f011a30cf26ed05cac3375571b3e449682616b7d945d1048659c9ee08d0bfb9709f4164e4bc1372b91ebd23fa74c1592738d3d16ffe249b6027e203956f8fe42e9513d7f66f10f10ed701aae5d50a6bfcf6c127e3f05544a3
msg2 ={'iv': '737561146ff8194f45290f5766ed6aba', 'encrypted_flag': '39c99bf2f0c14678d6a5416faef954b5893c316fc3c48622ba1fd6a9fe85f3dc72a29c394cf4bc8aff6a7b21cae8e12c'}
msg = {"iv": "3a7b23cc7c17c1aeb3ef9d4853080372", "encrypted_flag": "4389beac1a46730ae70eb1c1bf2a3449d53ce16fc2760b3acd50c5e442235989"}
b =  197395083814907028991785772714920885908249341925650951555219049411298436217190605190824934787336279228785809783531814507661385111220639329358048196339626065676869119737979175531770768861808581110311903548567424039264485661330995221907803300824165469977099494284722831845653985392791480264712091293580274947132480402319812110462641143884577706335859190668240694680261160210609506891842793868297672619625924001403035676872189455767944077542198064499486164431451944

x = pow(A,b,p)
print (x)