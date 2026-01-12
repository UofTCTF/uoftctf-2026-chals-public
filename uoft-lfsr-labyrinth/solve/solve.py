"""
solver.

It does four steps:
1) Read public data (taps, keystream, filter ANF).
2) Build one small annihilator polynomial for z=0 and z=1 (degree <= 3).
3) Encode the LFSR + annihilator equations to CNF and solve with SAT.
4) Derive the key from the recovered 48-bit state and decrypt.
"""

import json
from itertools import combinations
from pathlib import Path
from pysat.formula import CNF, IDPool
from pysat.solvers import Glucose4
import crypto  


def eval_anf(bits, terms):
    """Evaluate the filter ANF on a 7-bit vector."""
    acc = 0
    for mon in terms:
        prod = 1
        for i in mon:
            prod &= bits[i]
            if not prod:
                break
        acc ^= prod
    return acc


def build_annihilator(filter_terms, target_side):
    """
    Return one degree<=3 annihilator polynomial for the 7-bit filter.
    target_side=1: polynomial vanishes when f=1 (use with z=1)
    target_side=0: polynomial vanishes when f=0 (use with z=0)
    """
    mons = [()]
    for d in range(1, 4):
        mons += list(combinations(range(7), d))

    # truth table of f
    f_tt = []
    for mask in range(1 << 7):
        bits = [(mask >> i) & 1 for i in range(7)]
        f_tt.append(eval_anf(bits, filter_terms))

    # Build rows (bitmasks of monomials that evaluate to 1) where f == target_side.
    rows = []
    for mask, val in enumerate(f_tt):
        if val != target_side:
            continue
        bits = [(mask >> i) & 1 for i in range(7)]
        row = 0
        for j, mon in enumerate(mons):
            v = 1
            for i in mon:
                v &= bits[i]
                if not v:
                    break
            if v:
                row |= 1 << j
        rows.append(row)

    def nullspace_basis(rows, ncols):
        """Simple GF(2) row reduction to get a basis of the nullspace."""
        rows = rows[:]
        pivots = {}
        r = 0
        for c in range(ncols):
            pr = next((i for i in range(r, len(rows)) if (rows[i] >> c) & 1), None)
            if pr is None:
                continue
            rows[r], rows[pr] = rows[pr], rows[r]
            pivot_row = rows[r]
            pivots[c] = pivot_row
            for i in range(len(rows)):
                if i != r and ((rows[i] >> c) & 1):
                    rows[i] ^= pivot_row
            r += 1
            if r == len(rows):
                break

        pivot_cols = set(pivots.keys())
        free_cols = [c for c in range(ncols) if c not in pivot_cols]
        pivot_items = sorted(pivots.items(), reverse=True)

        basis = []
        for fcol in free_cols:
            vec = 1 << fcol
            for c, row in pivot_items:
                other = row & ~(1 << c)
                parity = (other & vec).bit_count() % 2
                if parity:
                    vec |= 1 << c
                else:
                    vec &= ~(1 << c)
            basis.append(vec)
        return basis, mons

    basis, mons = nullspace_basis(rows, len(mons))
    vec = basis[0]
    poly = [mons[i] for i in range(len(mons)) if (vec >> i) & 1]
    return poly


def solve_instance(data):
    L = data["L"]
    fb = data["feedback_taps"]
    ftaps = data["filter_taps"]
    terms = [tuple(t) for t in data["filter_terms"]]
    ks = data["keystream"]

    # Single annihilator per side (degree <=3).
    ann_f = build_annihilator(terms, target_side=1)
    ann_f1 = build_annihilator(terms, target_side=0)

    pool = IDPool(start_from=L + 1)
    cnf = CNF()

    # b[t]: state[0]=b[t], state[1]=b[t-1], ...
    tmin, tmax = - (L - 1), len(ks)
    b = {t: pool.id() for t in range(tmin, tmax + 1)}

    def and2(a, bvar):
        # o = a AND bvar
        o = pool.id()
        cnf.extend([[-a, -bvar, o], [a, -o], [bvar, -o]])
        return o

    def xor2(a, bvar):
        # o = a XOR bvar
        o = pool.id()
        cnf.extend([[-a, -bvar, -o], [-a, bvar, o], [a, -bvar, o], [a, bvar, -o]])
        return o

    def xor_chain(vs):
        if len(vs) == 1:
            return vs[0]
        cur = vs[0]
        for v in vs[1:]:
            cur = xor2(cur, v)
        return cur

    # LFSR recurrence: b[t+1] = xor(feedback taps)
    for t in range(0, len(ks)):
        taps = [b[t - off] for off in fb]
        eq = xor_chain([b[t + 1]] + taps)
        cnf.append([-eq])  # XOR(...) == 0

    # Annihilator equations per timestep (pick annihilator based on keystream bit)
    for t, z in enumerate(ks):
        taps = [b[t - off] for off in ftaps]
        poly = ann_f if z == 1 else ann_f1
        rhs = 0
        mon_vars = []
        for mon in poly:
            if len(mon) == 0:
                rhs ^= 1
            elif len(mon) == 1:
                mon_vars.append(taps[mon[0]])
            else:
                cur = taps[mon[0]]
                for idx in mon[1:]:
                    cur = and2(cur, taps[idx])
                mon_vars.append(cur)
        eq = xor_chain(mon_vars)
        cnf.append([eq] if rhs else [-eq])

    # Direct keystream checks to prune spurious solutions.
    check_count = min(40, len(ks))
    for t in range(check_count):
        taps = [b[t - off] for off in ftaps]
        rhs = 0
        mon_vars = []
        for mon in terms:
            if len(mon) == 0:
                rhs ^= 1
            elif len(mon) == 1:
                mon_vars.append(taps[mon[0]])
            else:
                cur = taps[mon[0]]
                for idx in mon[1:]:
                    cur = and2(cur, taps[idx])
                mon_vars.append(cur)
        zvar = xor_chain(mon_vars)
        want = ks[t] ^ rhs
        cnf.append([zvar] if want else [-zvar])

    solver = Glucose4(bootstrap_with=cnf.clauses)
    assert solver.solve()
    model = set(solver.get_model())

    def val(var):
        return 1 if var in model else 0

    state_bits = [val(b[-i]) for i in range(0, L)]
    return state_bits


def main():
    data = json.load(open("challenge.json"))
    state_bits = solve_instance(data)
    pt = crypto.decrypt(bytes.fromhex(data["nonce"]), bytes.fromhex(data["ct"]), state_bits)
    print(pt.decode())


if __name__ == "__main__":
    main()
