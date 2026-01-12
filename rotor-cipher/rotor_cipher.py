import numpy as np
import string
import secrets

try:
    from rotor_design import RX, RY, RZ, Ref
    is_placeholder = False
except:
    # Placeholders
    RX = ("EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q")
    RY = ("AJDKSIRUXBLHWTMCQGZNPYFVOE", "E")
    RZ = ("BDFHJLCPRTXVZNYEIWGAKMUSQO", "V")
    Ref = [('A','Y'), ('B','R'), ('C','U'), ('D','H'), ('E','Q'), ('F','S'),
           ('G','L'), ('I','P'), ('J','X'), ('K','N'), ('M','O'), ('T','Z'),
           ('V','W')]
    is_placeholder = True
N = 26
ALPHA = string.ascii_uppercase

# helper function for formatting the flag
# please check that your wirings are consistent with the provided
# log before submitting.
def format_flag(RX, RY, RZ, Ref):
    # ignore notches
    assert all(map(lambda c : c in ALPHA, RX[0])) and \
           all(map(lambda c : c in ALPHA, RY[0])) and \
           all(map(lambda c : c in ALPHA, RZ[0]))
    x_rotor = "".join(RX[0])
    y_rotor = "".join(RY[0])
    z_rotor = "".join(RZ[0])
    # reflector should be cannonical
    assert all(map(lambda t : len(t) == 2 and ord(t[0]) < ord(t[1]), Ref))
    assert Ref == sorted(Ref)
    ref_str = "_".join(map("".join, Ref))
    return "uoftctf{{{}_{}_{}_{}}}".format(x_rotor, y_rotor, z_rotor, ref_str)

if is_placeholder:
    # This is the placeholder flag for the fake wirings
    # Please generate the flag for the real wirings
    # You lose aura if you submit this flag, we can see the submitted flags
    assert format_flag(RX, RY, RZ, Ref) == "uoftctf{EKMFLGDQVZNTOWYHXUSPAIBRCJ_AJDKSIRUXBLHWTMCQGZNPYFVOE_BDFHJLCPRTXVZNYEIWGAKMUSQO_AY_BR_CU_DH_EQ_FS_GL_IP_JX_KN_MO_TZ_VW}"

def idx(c):
    return ord(c) - ord("A")

class Rotor:
    def __init__(self, R, init_pos):
        rotor_perm, turn_notch = R
        assert sorted(rotor_perm) == list(ALPHA)
        rotor_perm = list(map(idx, rotor_perm))
        self.rotor_perm = np.eye(N, dtype=int)[rotor_perm]
        self.turn_notch = idx(turn_notch)
        assert init_pos in ALPHA
        self.pos = idx(init_pos)
    
    def rotate(self):
        propagate = self.pos == self.turn_notch
        self.pos = (self.pos + 1) % N
        return propagate
    
    def curr_perm(self):
        idx = (np.arange(N, dtype=int) + self.pos) % N
        return self.rotor_perm[np.ix_(idx, idx)].T

class Involution:
    def __init__(self, P):
        # check canonical
        assert all(map(lambda t : len(t) == 2 and ord(t[0]) < ord(t[1]), P))
        assert P == sorted(P)
        involution_perm = np.arange(N, dtype=int)
        for u,v in P:
            u = idx(u)
            v = idx(v)
            involution_perm[u], involution_perm[v] = involution_perm[v], involution_perm[u]
        self.involution_perm = np.eye(N, dtype=int)[involution_perm]
        assert (self.involution_perm @ self.involution_perm == np.eye(N, dtype=int)).all()
    
    def perm(self):
        return self.involution_perm.T

class RotorCipher:
    def __init__(self, Ref, R, P, R0):
        self.plugboard = Involution(P)
        self.rotors = [Rotor(*r_r0) for r_r0 in zip(R, R0)]
        self.reflector = Involution(Ref)
    
    def encrypt(self, s):
        # Note: decryption is the same as encryption
        t = ""
        for c in s:
            for i in range(len(self.rotors)):
                if not self.rotors[i].rotate():
                    break
            vec = np.zeros(N, dtype=int)
            vec[ALPHA.index(c)] = 1
            vec = self.plugboard.perm() @ vec
            for i in range(len(self.rotors)):
                vec = self.rotors[i].curr_perm() @ vec
            vec = self.reflector.perm() @ vec
            for i in range(len(self.rotors)-1, -1, -1):
                vec = np.linalg.inv(self.rotors[i].curr_perm()) @ vec
            vec = self.plugboard.perm() @ vec
            t += ALPHA[np.argmax(vec)]
        return t
               

if __name__ == "__main__":
    if is_placeholder:
        print("Using placeholder rotor wiring.")
    sample_plaintext = "The quick brown fox jumps over the lazy dog"
    sample_plaintext = sample_plaintext.upper().replace(" ", "")
    sample_setting = ["O", "J", "B"]
    sample_plugboard = [("B", "P"), ("C", "D"), ("F", "W"), ("N", "X"), ("S", "V"), ("U", "Y")]
    cipher = RotorCipher(Ref, [RX, RY, RZ], sample_plugboard, sample_setting)
    sample_ciphertext = cipher.encrypt(sample_plaintext)
    cipher = RotorCipher(Ref, [RX, RY, RZ], sample_plugboard, sample_setting)
    sample_decrypt = cipher.encrypt(sample_ciphertext)
    print("Sample Plaintext:", sample_plaintext)
    print("Sample Ciphertext:", sample_ciphertext)
    print("Sample Decrypt:", sample_decrypt)
    assert sample_plaintext == sample_decrypt
    print("Begin Challenge Log")
    DAYS = 10
    MESSAGES = 100
    rng = secrets.SystemRandom()
    rotors = {"X": RX, "Y": RY, "Z": RZ}
    letters = list(ALPHA)
    for d in range(DAYS):
        # random rotor order
        rotor_order = ["X", "Y", "Z"]
        rng.shuffle(rotor_order)
        # random plugboard
        rng.shuffle(letters)
        plugboard = []
        for i in range(6):
            t = (letters[2*i], letters[2*i+1])
            plugboard.append((min(t), max(t)))
        plugboard.sort()
        # random setting
        rng.shuffle(letters)
        setting = letters[:3]
        print("{}: rotor: {}, plugboard: {} setting: {}".format(d, rotor_order, plugboard, setting))
        for m in range(MESSAGES):
            
            # random message
            message = "".join(rng.choice(letters) for i in range(6))
            cipher = RotorCipher(Ref, list(map(rotors.get, rotor_order)), plugboard, setting)
            ct = cipher.encrypt(message)
            print("    {:2}: msg: {} ct: {}".format(m, message, ct))
            
            



