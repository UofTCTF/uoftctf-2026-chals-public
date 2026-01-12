#!/usr/bin/env python3
import angr
import claripy
# run `upx -d checker` before executing this script
def main():
    proj = angr.Project("./checker", auto_load_libs=False)
    flag_len = 44
    flag_chars = [claripy.BVS(f"b{i}", 8) for i in range(flag_len)]
    flag = claripy.Concat(*flag_chars)
    stdin = claripy.Concat(flag, claripy.BVV(b"\n"))
    simfile = angr.SimFileStream(name="stdin", content=stdin, has_end=False)
    state = proj.factory.full_init_state(stdin=simfile)
    prefix = b"uoftctf{"
    for i in range(len(prefix)):
        state.solver.add(flag_chars[i] == prefix[i])
    state.solver.add(flag_chars[flag_len - 3] == ord("}"))

    simgr = proj.factory.simgr(state)

    def success(s):
        out = s.posix.dumps(1)
        return b"Yes" in out

    simgr.explore(find=success)

    if simgr.found:
        found = simgr.found[0]
        model = found.solver.eval(flag, cast_to=bytes)
        print(model.decode("ascii", errors="replace").strip())
    else:
        print("No solution found")

if __name__ == "__main__":
    main()
