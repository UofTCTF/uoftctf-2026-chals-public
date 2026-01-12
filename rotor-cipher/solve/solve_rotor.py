import itertools
import string
import sys
sys.path.append("..")
import rotor_cipher

ALPHA = string.ascii_uppercase
N = 26

def idx(c):
    return ord(c) - ord("A")

def alp(i):
    return chr(i + ord("A"))

def ac(a, b):
    L = []
    for c in a:
        L.append(b[idx(c)])
    return L

def acr(*args):
    if len(args) == 1:
        return args[0]
    else:
        return ac(args[0], acr(*args[1:]))

def P(k):
    k = k % N
    return list(ALPHA[k:] + ALPHA[:k])

def inv(p):
    L = [None]*N
    for i in range(N):
        L[idx(p[i])] = chr(i + ord("A"))
    return L

def make_involution(swaps):
    L = list(ALPHA)
    for swap in swaps:
        assert L[idx(swap[0])] == swap[0] and L[idx(swap[1])] == swap[1]
        L[idx(swap[0])], L[idx(swap[1])] = L[idx(swap[1])], L[idx(swap[0])]
    return L

def cycles_of(p):
    seen = [False] * N
    cycles = []
    for i in range(N):
        if seen[i]:
            continue
        # find orbit starting at i
        cur = i
        orbit = []
        while not seen[cur]:
            seen[cur] = True
            orbit.append(cur)
            cur = idx(p[cur])
        cycles.append(orbit)
    return cycles

def group_cycles_by_length(cycles):
    groups = {}
    for cycle in cycles:
        if len(cycle) not in groups:
            groups[len(cycle)] = []
        groups[len(cycle)].append(cycle)
    return groups

def build_conjugators_sigma1_sigma0(sigma0, sigma1):
    c0 = group_cycles_by_length(cycles_of(sigma0))
    c1 = group_cycles_by_length(cycles_of(sigma1))

    V = [-1] * N
    used_y = [False] * N
    results = []

    lengths = sorted(c0.keys())

    def try_assign_cycle(cyc0, cyc1, rot):
        L = len(cyc0)
        newly = []
        for j, x in enumerate(cyc0):
            y = cyc1[(j + rot) % L]
            if V[x] != -1 and V[x] != y:
                # conflict
                for xx in newly:
                    used_y[V[xx]] = False
                    V[xx] = -1
                return None
            if V[x] == -1:
                if used_y[y]:
                    for xx in newly:
                        used_y[V[xx]] = False
                        V[xx] = -1
                    return None
                V[x] = y
                used_y[y] = True
                newly.append(x)
        return newly

    def undo(newly):
        for x in newly:
            used_y[V[x]] = False
            V[x] = -1

    def recurse_length(li):
        if li == len(lengths):
            results.append(V.copy())
            return

        L = lengths[li]
        list0 = c0[L]
        list1 = c1[L]

        for perm_list1 in itertools.permutations(list1):
            # recurse through cycles within this length group
            def recurse_cycle(ci):
                if ci == len(list0):
                    recurse_length(li + 1)
                    return
                cyc0 = list0[ci]
                cyc1 = perm_list1[ci]
                for rot in range(len(cyc0)):
                    newly = try_assign_cycle(cyc0, cyc1, rot)
                    if newly is None:
                        continue
                    recurse_cycle(ci + 1)
                    undo(newly)

            recurse_cycle(0)

    recurse_length(0)
    return results

def parse_daily_log(s):
    perms = [[None for _ in range(26)] for _ in range(6)]
    for row in s.split("\n")[1:]:
        msg_pos = row.index("msg: ") + 5
        msg = row[msg_pos:msg_pos+6]
        ct_pos = row.index("ct: ") + 4
        ct = row[ct_pos:ct_pos+6]
        for i in range(6):
            assert perms[i][idx(msg[i])] is None or perms[i][idx(msg[i])] == ct[i]
            perms[i][idx(msg[i])] = ct[i]
    for i in range(6):
        if perms[i].count(None) == 1:
            perms[i][perms[i].index(None)] = list(set(ALPHA) - set(perms[i]))[0]
    return perms

def solve_fast_rotor(A, s, init_pos):
    B = []
    for i in range(6):
        B.append(acr(P(-(i+1)), s, A[i], s, P(i+1)))
    C = []
    for i in range(5):
        C.append(ac(B[i], B[i+1]))
    candidates = build_conjugators_sigma1_sigma0(C[0], C[1])
    solutions = []
    for candidate in candidates:
        accepted = True
        for i in range(len(C)-1):
            s = C[i]
            t = C[i + 1]
            for x in range(N):
                if candidate[idx(s[x])] != idx(t[candidate[x]]):
                    accepted = False
        if accepted:
            solutions.append(list(map(alp, candidate)))
    assert len(solutions) == 1
    candidate_rotors = []
    for off in range(26):
        R = [None] * N
        x = "A"
        for c in P(off):
            R[idx(x)] = c
            x = solutions[0][idx(x)]
        R = ac(P(-idx(init_pos)), R)
        candidate_rotors.append(R)
    return candidate_rotors

def involution_perm_to_swaps(perm):
    L = []
    for i in range(N):
        if perm[i] > alp(i):
            L.append((alp(i), perm[i]))
    return L

x_right_log = """3: rotor: ['X', 'Y', 'Z'], plugboard: [('B', 'R'), ('C', 'D'), ('H', 'K'), ('I', 'X'), ('M', 'Q'), ('Y', 'Z')] setting: ['Y', 'Q', 'B']
     0: msg: RFWQMH ct: PJIOHE
     1: msg: QVCXYM ct: IKOMQL
     2: msg: ELPLXE ct: MXBYXH
     3: msg: YEXETT ct: JNRKRB
     4: msg: HTQDZQ ct: CTLSED
     5: msg: JVZTZV ct: YKZCEP
     6: msg: CCNNLS ct: HYKPUX
     7: msg: GJBHTY ct: BFPURI
     8: msg: OXCUJV ct: WLOHGP
     9: msg: GBTDSP ct: BASSSV
    10: msg: JHRQCZ ct: YZXOKG
    11: msg: HRHPWK ct: CSDNNW
    12: msg: DYIHXV ct: XCWUXP
    13: msg: ZMGATM ct: TOAGRL
    14: msg: YFFVOI ct: JJJFAY
    15: msg: BSCJDI ct: GROWPY
    16: msg: EHKZOZ ct: MZNZAG
    17: msg: UBWNFZ ct: SAIPIG
    18: msg: OXPCYG ct: WLBTQZ
    19: msg: BLYRPB ct: GXURDT
    20: msg: DZQJWJ ct: XHLWNO
    21: msg: PFWFOX ct: RJIVAS
    22: msg: QXOEJK ct: ILCKGW
    23: msg: KBTCBV ct: AASTVP
    24: msg: ROWYON ct: PMILAF
    25: msg: WLBPUG ct: OXPNLZ
    26: msg: TZHRRP ct: ZHDRTV
    27: msg: CPQMYV ct: HDLXQP
    28: msg: QMLMGC ct: IOQXJA
    29: msg: LRIKML ct: LSWEHM
    30: msg: KYTHCH ct: ACSUKE
    31: msg: HQBRFI ct: CWPRIY
    32: msg: RRIOJT ct: PSWQGB
    33: msg: KSYDPL ct: ARUSDM
    34: msg: LFEEST ct: LJVKSB
    35: msg: YNIGBD ct: JEWAVQ
    36: msg: JXYUIZ ct: YLUHFG
    37: msg: FMERBN ct: VOVRVF
    38: msg: ZRQHZG ct: TSLUEZ
    39: msg: NLYZJP ct: NXUZGV
    40: msg: SKFPJK ct: UVJNGW
    41: msg: NCVCIY ct: NYETFI
    42: msg: MFLKGN ct: EJQEJF
    43: msg: LNNBSQ ct: LEKISD
    44: msg: JOSOOG ct: YMTQAZ
    45: msg: KDGTWS ct: APACNX
    46: msg: XVMVKM ct: DKMFCL
    47: msg: RQEPEA ct: PWVNZC
    48: msg: FREFWH ct: VSVVNE
    49: msg: YOLUOV ct: JMQHAP
    50: msg: MYUJGL ct: ECYWJM
    51: msg: NRXROC ct: NSRRAA
    52: msg: MJVGDZ ct: EFEAPG
    53: msg: NPERKY ct: NDVRCI
    54: msg: JCTDAQ ct: YYSSOD
    55: msg: SGIWNT ct: UGWJWB
    56: msg: BNYYOE ct: GEULAH
    57: msg: OTLGTW ct: WTQARK
    58: msg: UBPDFS ct: SABSIX
    59: msg: RENOZH ct: PNKQEE
    60: msg: PISJVT ct: RUTWBB
    61: msg: NZBEXR ct: NHPKXR
    62: msg: EZDYZG ct: MHHLEZ
    63: msg: RKDHZZ ct: PVHUEG
    64: msg: SCZFLQ ct: UYZVUD
    65: msg: JFRHXA ct: YJXUXC
    66: msg: FYPARS ct: VCBGTX
    67: msg: SSYUUD ct: URUHLQ
    68: msg: ICNRWM ct: QYKRNL
    69: msg: WJVALN ct: OFEGUF
    70: msg: MOILMK ct: EMWYHW
    71: msg: LJGVIS ct: LFAFFX
    72: msg: QKGAFB ct: IVAGIT
    73: msg: IAKUGS ct: QBNHJX
    74: msg: ZGTWNK ct: TGSJWW
    75: msg: HCMBVO ct: CYMIBJ
    76: msg: BVXNZN ct: GKRPEF
    77: msg: KPTSPQ ct: ADSDDD
    78: msg: EPKYCD ct: MDNLKQ
    79: msg: EVUSKR ct: MKYDCR
    80: msg: LMIRAR ct: LOWROR
    81: msg: XSJGHA ct: DRFAMC
    82: msg: AIBCDI ct: KUPTPY
    83: msg: BJGWGD ct: GFAJJQ
    84: msg: HPDBUQ ct: CDHILD
    85: msg: VKAHRB ct: FVGUTT
    86: msg: WREMJO ct: OSVXGJ
    87: msg: XLKBOC ct: DXNIAA
    88: msg: PCFURA ct: RYJHTC
    89: msg: LMURRP ct: LOYRTV
    90: msg: TPZSMG ct: ZDZDHZ
    91: msg: DMXFGI ct: XORVJY
    92: msg: TNEKIE ct: ZEVEFH
    93: msg: TYHLHR ct: ZCDYMR
    94: msg: XLQOEY ct: DXLQZI
    95: msg: OZACWS ct: WHGTNX
    96: msg: CIVMPC ct: HUEXDA
    97: msg: BAOIRO ct: GBCBTJ
    98: msg: VVSIGX ct: FKTBJS
    99: msg: CXXJUK ct: HLRWLW"""
x_s = make_involution([('B', 'R'), ('C', 'D'), ('H', 'K'), ('I', 'X'), ('M', 'Q'), ('Y', 'Z')])
x_A = parse_daily_log(x_right_log)
# save setting for later reflector solving
x_setting = ['Y', 'Q', 'B']
# fix missing
x_A[1][20] = 'I'
x_A[1][22] = 'Q'
x_A[5][5] = 'N'
x_A[5][20] = 'U'
x_rotor_cands = solve_fast_rotor(x_A, x_s, 'Y')
print("X candidates", list(map(lambda x:"".join(x), x_rotor_cands)))

y_right_log = """0: rotor: ['Y', 'Z', 'X'], plugboard: [('D', 'X'), ('H', 'I'), ('J', 'S'), ('N', 'Z'), ('O', 'R'), ('P', 'Y')] setting: ['J', 'L', 'A']
     0: msg: CXAVMP ct: JKFZPL
     1: msg: IQIZLY ct: RRHVAY
     2: msg: VMZVCC ct: GJTZVB
     3: msg: KIFVBE ct: AIAZWS
     4: msg: EOHKPS ct: HSIMME
     5: msg: XNYOCQ ct: TDSOVN
     6: msg: JKRZTD ct: CXRVTI
     7: msg: CBYUXM ct: JCSQOH
     8: msg: AWOCRZ ct: KTNISZ
     9: msg: SQVWEN ct: ZRQBQQ
    10: msg: FFPJZX ct: YLMPDW
    11: msg: HXGUMX ct: EKXQPW
    12: msg: OIDHYU ct: LIUXHV
    13: msg: OLCOSL ct: LFKORP
    14: msg: RVYKLH ct: IZSMAM
    15: msg: LKRJQX ct: OXRPEW
    16: msg: PGAANG ct: UAFGJA
    17: msg: SERQVG ct: ZERUCA
    18: msg: YEDGYJ ct: FEUAHT
    19: msg: VECKYB ct: GEKMHC
    20: msg: UTBHPV ct: PWJXMU
    21: msg: XOCEKR ct: TSKYIF
    22: msg: KAWVBP ct: AGWZWL
    23: msg: MZKAXE ct: BVCGOS
    24: msg: EKDZPN ct: HXUVMQ
    25: msg: PFRZEX ct: ULRVQW
    26: msg: LQMKWR ct: ORPMBF
    27: msg: HLOMCK ct: EFNKVO
    28: msg: UIQPSZ ct: PIVJRZ
    29: msg: LUHGCF ct: OHIAVR
    30: msg: EZSSKU ct: HVYNIV
    31: msg: DQYAGZ ct: WRSGFZ
    32: msg: NVFJYE ct: NZAPHS
    33: msg: HQVCFH ct: ERQIGM
    34: msg: GXGBSG ct: VKXWRA
    35: msg: BEIBOT ct: MEHWXJ
    36: msg: PRXNZA ct: UQGSDG
    37: msg: PVUIHY ct: UZDCYY
    38: msg: QGFPTQ ct: QAAJTN
    39: msg: UTWLND ct: PWWTJI
    40: msg: URMYOR ct: PQPEXF
    41: msg: UIDGDQ ct: PIUAZN
    42: msg: UTQHVZ ct: PWVXCZ
    43: msg: TESAHR ct: XEYGYF
    44: msg: XXUTGJ ct: TKDLFT
    45: msg: LOUZZL ct: OSDVDP
    46: msg: QDSHKP ct: QNYXIL
    47: msg: UHHTIC ct: PUILKB
    48: msg: LXEQNE ct: OKLUJS
    49: msg: BGUBBG ct: MADWWA
    50: msg: QPEVEW ct: QYLZQX
    51: msg: QPGXAM ct: QYXHLH
    52: msg: TUJCJF ct: XHBINR
    53: msg: ANEHZV ct: KDLXDU
    54: msg: ZKKSOV ct: SXCNXU
    55: msg: EOOTJK ct: HSNLNO
    56: msg: GVGFBD ct: VZXFWI
    57: msg: AGREEG ct: KARYQA
    58: msg: TULWMJ ct: XHEBPT
    59: msg: GBTYNP ct: VCZEJL
    60: msg: ECAYEY ct: HBFEQY
    61: msg: PLHAUG ct: UFIGUA
    62: msg: SGDZRN ct: ZAUVSQ
    63: msg: FDAEQJ ct: YNFYET
    64: msg: GDRCAY ct: VNRILY
    65: msg: XRDEWP ct: TQUYBL
    66: msg: FQYYRX ct: YRSESW
    67: msg: ENRRMV ct: HDRDPU
    68: msg: RQFNPW ct: IRASMX
    69: msg: ACNUNF ct: KBOQJR
    70: msg: ZNCJFK ct: SDKPGO
    71: msg: MEEZMF ct: BELVPR
    72: msg: NLMJVJ ct: NFPPCT
    73: msg: CEBKKV ct: JEJMIU
    74: msg: OUGQOS ct: LHXUXE
    75: msg: IVWZBY ct: RZWVWY
    76: msg: JESNFP ct: CEYSGL
    77: msg: CHTUKA ct: JUZQIG
    78: msg: TZLHTA ct: XVEXTG
    79: msg: ARMXYL ct: KQPHHP
    80: msg: LMFZRH ct: OJAVSM
    81: msg: SCVOFN ct: ZBQOGQ
    82: msg: GSZMNI ct: VOTKJD
    83: msg: BCYYKK ct: MBSEIO
    84: msg: LQPGWA ct: ORMABG
    85: msg: LCFFLY ct: OBAFAY
    86: msg: SBOMTG ct: ZCNKTA
    87: msg: HOBDXT ct: ESJROJ
    88: msg: APNNAQ ct: KYOSLN
    89: msg: XGXDES ct: TAGRQE
    90: msg: AUZOYH ct: KHTOHM
    91: msg: BRVDRX ct: MQQRSW
    92: msg: KJHDED ct: AMIRQI
    93: msg: SURNCD ct: ZHRSVI
    94: msg: FIAZAJ ct: YIFVLT
    95: msg: UMIAMN ct: PJHGPQ
    96: msg: KBLMNZ ct: ACEKJZ
    97: msg: PISDRV ct: UIYRSU
    98: msg: MPQHSU ct: BYVXRV
    99: msg: PAFJPW ct: UGAPMX"""
y_s = make_involution([('D', 'X'), ('H', 'I'), ('J', 'S'), ('N', 'Z'), ('O', 'R'), ('P', 'Y')])
y_A = parse_daily_log(y_right_log)
y_rotor_cands = solve_fast_rotor(y_A, y_s, 'J')
print("Y candidates", list(map(lambda x:"".join(x), y_rotor_cands)))

z_right_log = """2: rotor: ['Z', 'Y', 'X'], plugboard: [('B', 'P'), ('D', 'Z'), ('F', 'Q'), ('I', 'L'), ('J', 'M'), ('W', 'X')] setting: ['Q', 'D', 'L']
     0: msg: WDNGIA ct: GRLLFW
     1: msg: SZAFVK ct: PPTVBB
     2: msg: NIZYYM ct: MHMDRV
     3: msg: GTEDFN ct: WEHYIN
     4: msg: EGRZAI ct: HUBRMF
     5: msg: ZIKHMN ct: DHCNAN
     6: msg: ZHESPK ct: DIHTNB
     7: msg: DSFUJF ct: ZAGKGI
     8: msg: ZWXQOD ct: DVJMOP
     9: msg: JCOSQC ct: UKSTXJ
    10: msg: KIURCE ct: XHPZWZ
    11: msg: GJIAGU ct: WBVAJH
    12: msg: VPNLLW ct: VZLGSA
    13: msg: NYXZUI ct: MYJRZF
    14: msg: PHWPTG ct: SIWJEO
    15: msg: KPWUHE ct: XZWKKZ
    16: msg: DCCPAT ct: ZKKJML
    17: msg: ZILGOL ct: DHNLOT
    18: msg: MEGMWP ct: NTFQCD
    19: msg: NLRQVY ct: MQBMBS
    20: msg: HOYKOI ct: ENYUOF
    21: msg: RFJQSW ct: RFXMLA
    22: msg: YPYKDK ct: AZYUDB
    23: msg: KFEYFF ct: XFHDII
    24: msg: XXHLWY ct: KMEGCS
    25: msg: DHHXQD ct: ZIEIXP
    26: msg: WVLRYY ct: GWNZRS
    27: msg: QQVIKT ct: ILIXHL
    28: msg: TVUATV ct: FWPAEM
    29: msg: IOLWZM ct: QNNWUV
    30: msg: WYSJNW ct: GYOPPA
    31: msg: JDCZBY ct: URKRVS
    32: msg: EHMCCT ct: HIZBWL
    33: msg: JFIVOO ct: UFVFOG
    34: msg: YISORG ct: AHOEYO
    35: msg: BDIEUA ct: ORVOZW
    36: msg: ZOLHLU ct: DNNNSH
    37: msg: HHFZHK ct: EIGRKB
    38: msg: CSPHUN ct: LAUNZN
    39: msg: OUAISV ct: BGTXLM
    40: msg: PSKYOC ct: SACDOJ
    41: msg: EARTMO ct: HSBSAG
    42: msg: QZOBGS ct: IPSCJY
    43: msg: HFNYBK ct: EFLDVB
    44: msg: BQCPNE ct: OLKJPZ
    45: msg: YQPZMZ ct: ALURAE
    46: msg: MUPNFN ct: NGUHIN
    47: msg: SRLFRV ct: PDNVYM
    48: msg: VDFDME ct: VRGYAZ
    49: msg: PYYQRI ct: SYYMYF
    50: msg: YAYTYA ct: ASYSRW
    51: msg: ROBWHY ct: RNRWKS
    52: msg: VQXBPZ ct: VLJCNE
    53: msg: YJEKMJ ct: ABHUAC
    54: msg: VEVPEA ct: VTIJTW
    55: msg: AIQDDL ct: YHDYDT
    56: msg: KAVEXF ct: XSIOQI
    57: msg: BLSVPU ct: OQOFNH
    58: msg: YIAUCE ct: AHTKWZ
    59: msg: ENNMDB ct: HOLQDK
    60: msg: ASFKCT ct: YAGUWL
    61: msg: XPXWDT ct: KZJWDL
    62: msg: JKDVEI ct: UCQFTF
    63: msg: NZSIKC ct: MPOXHJ
    64: msg: VYFPRH ct: VYGJYU
    65: msg: VHJLBX ct: VIXGVQ
    66: msg: VZOXHU ct: VPSIKH
    67: msg: EDNTBJ ct: HRLSVC
    68: msg: RDNQBT ct: RRLMVL
    69: msg: JMDFXJ ct: UXQVQC
    70: msg: ZCYFMM ct: DKYVAV
    71: msg: TBJXUI ct: FJXIZF
    72: msg: QHPASO ct: IIUALG
    73: msg: HVNMYZ ct: EWLQRE
    74: msg: WCOKVE ct: GKSUBZ
    75: msg: OMOMPN ct: BXSQNN
    76: msg: FDCBRB ct: TRKCYK
    77: msg: ELTYXW ct: HQADQA
    78: msg: ULHXLK ct: JQEISB
    79: msg: ITDNJG ct: QEQHGO
    80: msg: NQGGHA ct: MLFLKW
    81: msg: ATTEEA ct: YEAOTW
    82: msg: NCHDHV ct: MKEYKM
    83: msg: FZZKDA ct: TPMUDW
    84: msg: YPSCGQ ct: AZOBJX
    85: msg: JGSMMI ct: UUOQAF
    86: msg: VWPMTO ct: VVUQEG
    87: msg: DRRVAM ct: ZDBFMV
    88: msg: MMJMWZ ct: NXXQCE
    89: msg: WDKIIJ ct: GRCXFC
    90: msg: XBDQBW ct: KJQMVA
    91: msg: IZWMOR ct: QPWQOR
    92: msg: WUPTBM ct: GGUSVV
    93: msg: ZUIOLB ct: DGVESK
    94: msg: BOJMDT ct: ONXQDL
    95: msg: VAKQFJ ct: VSCMIC
    96: msg: GQDNYL ct: WLQHRT
    97: msg: NUOWTP ct: MGSWED
    98: msg: TMWTFS ct: FXWSIY
    99: msg: NVXWUE ct: MWJWZZ"""
z_s = make_involution([('B', 'P'), ('D', 'Z'), ('F', 'Q'), ('I', 'L'), ('J', 'M'), ('W', 'X')])
z_A = parse_daily_log(z_right_log)
z_rotor_cands = solve_fast_rotor(z_A, z_s, 'Q')
print("Z candidates", list(map(lambda x:"".join(x), z_rotor_cands)))

# find which rotor candidate
sample_plaintext = "The quick brown fox jumps over the lazy dog"
sample_plaintext = sample_plaintext.upper().replace(" ", "")
sample_setting = ["O", "J", "B"]
sample_plugboard = [("B", "P"), ("C", "D"), ("F", "W"), ("N", "X"), ("S", "V"), ("U", "Y")]
target = "ZRMQPAFSYCICFLJSGQPPRAFRTEUEOCXDWVQ"

# first solve for exact x rotor and notch position using sample
iy = 0
iz = 0
for ix, notch in itertools.product(range(N), repeat=2):
    
    reflector_perm = acr(P(idx(x_setting[2])), inv(z_rotor_cands[iz]), P(-(idx(x_setting[2]))), 
                    P(idx(x_setting[1])), inv(y_rotor_cands[iy]), P(-(idx(x_setting[1]))), 
                    P(idx(x_setting[0])+1), inv(x_rotor_cands[ix]), P(-(idx(x_setting[0])+1)), 
                    x_s, x_A[0], x_s, 
                    P(idx(x_setting[0])+1), x_rotor_cands[ix], P(-(idx(x_setting[0])+1)),
                    P(idx(x_setting[1])), y_rotor_cands[iy], P(-idx(x_setting[1])),
                    P(idx(x_setting[2])), z_rotor_cands[iz], P(-idx(x_setting[2])))
    reflector = involution_perm_to_swaps(reflector_perm)

    RX = (x_rotor_cands[ix], alp(notch))
    RY = (y_rotor_cands[iy], "A")
    RZ = (z_rotor_cands[iz], "A")
    cipher = rotor_cipher.RotorCipher(reflector, [RX, RY, RZ], sample_plugboard, sample_setting)
    sample_ciphertext = cipher.encrypt(sample_plaintext)
    if sample_ciphertext == target:
        print("ix, notch:", ix, alp(notch))
        break
# now that we have x rotor, let us solve y and z rotors
ix = 25
x_notch = 'R'

sample_plaintext = "RXEZYG"
sample_setting = ['M', 'G', 'D']
sample_plugboard = [('A', 'G'), ('F', 'P'), ('J', 'Z'), ('K', 'W'), ('R', 'U'), ('S', 'X')]
target = "BTXSQY"

for iy, iz in itertools.product(range(26), repeat=2):
    reflector_perm = acr(P(idx(x_setting[2])), inv(z_rotor_cands[iz]), P(-(idx(x_setting[2]))), 
                    P(idx(x_setting[1])), inv(y_rotor_cands[iy]), P(-(idx(x_setting[1]))), 
                    P(idx(x_setting[0])+1), inv(x_rotor_cands[ix]), P(-(idx(x_setting[0])+1)), 
                    x_s, x_A[0], x_s, 
                    P(idx(x_setting[0])+1), x_rotor_cands[ix], P(-(idx(x_setting[0])+1)),
                    P(idx(x_setting[1])), y_rotor_cands[iy], P(-idx(x_setting[1])),
                    P(idx(x_setting[2])), z_rotor_cands[iz], P(-idx(x_setting[2])))
    reflector = involution_perm_to_swaps(reflector_perm)

    RX = (x_rotor_cands[ix], x_notch)
    RY = (y_rotor_cands[iy], "A")
    RZ = (z_rotor_cands[iz], "A")
    cipher = rotor_cipher.RotorCipher(reflector, [RZ, RY, RX], sample_plugboard, sample_setting)
    sample_ciphertext = cipher.encrypt(sample_plaintext)
    if sample_ciphertext == target:
        print(ix, iy, iz)
        print(RX, RY, RZ)
        print(reflector)
        print("Candidate flag:", rotor_cipher.format_flag(RX, RY, RZ, reflector))