import argparse
import sys
from pathlib import Path

import json
import numpy as np
import torch
import torch.nn.functional as F
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(ROOT))

# import solve.deobbed_model as model_obf
import dist.model as model_obf


def apply_perm(x: torch.Tensor, perm: torch.Tensor) -> torch.Tensor:
    b, c, h, w = x.shape
    x = x.view(b, c, h * w)
    idx = perm.unsqueeze(0).expand(b, -1, -1)
    x = torch.gather(x, dim=2, index=idx)
    return x.view(b, c, h, w)


def invert_mix(x: torch.Tensor, weight: torch.Tensor) -> torch.Tensor:
    w = weight.view(weight.size(0), weight.size(1))
    w_inv = torch.linalg.inv(w).view(weight.size(0), weight.size(1), 1, 1)
    return F.conv2d(x, w_inv)


def aname(obf_map, name: str) -> str:
    return obf_map["attrs"].get(name, name)


def conv_bank(x: torch.Tensor, core, idx: int, obf_map) -> torch.Tensor:
    pack = int(getattr(core, aname(obf_map, "conv_meta_packed"))[idx].item())
    out_shift = int(getattr(core, aname(obf_map, "OUT_SHIFT")))
    in_shift = int(getattr(core, aname(obf_map, "IN_SHIFT")))
    kh_shift = int(getattr(core, aname(obf_map, "KH_SHIFT")))
    kw_shift = int(getattr(core, aname(obf_map, "KW_SHIFT")))
    woff_shift = int(getattr(core, aname(obf_map, "WOFF_SHIFT")))
    boff_shift = int(getattr(core, aname(obf_map, "BOFF_SHIFT")))
    out_bits = int(getattr(core, aname(obf_map, "OUT_BITS")))
    in_bits = int(getattr(core, aname(obf_map, "IN_BITS")))
    kh_bits = int(getattr(core, aname(obf_map, "KH_BITS")))
    kw_bits = int(getattr(core, aname(obf_map, "KW_BITS")))
    woff_bits = int(getattr(core, aname(obf_map, "WOFF_BITS")))
    boff_bits = int(getattr(core, aname(obf_map, "BOFF_BITS")))
    out_ch = ((pack >> out_shift) & ((1 << out_bits) - 1)) + 1
    in_ch = ((pack >> in_shift) & ((1 << in_bits) - 1)) + 1
    kh = (pack >> kh_shift) & ((1 << kh_bits) - 1)
    kw = (pack >> kw_shift) & ((1 << kw_bits) - 1)
    w_off = (pack >> woff_shift) & ((1 << woff_bits) - 1)
    b_off = (pack >> boff_shift) & ((1 << boff_bits) - 1)
    w = getattr(core, aname(obf_map, "w_flat"))[w_off : w_off + out_ch * in_ch * kh * kw].view(
        out_ch, in_ch, kh, kw
    )
    b = getattr(core, aname(obf_map, "b_flat"))[b_off : b_off + out_ch]
    return F.conv2d(x, w, b, stride=1, padding=1)


def op(core, obf_map, name: str) -> int:
    return int(getattr(core, aname(obf_map, name)))


def step(regs: list[torch.Tensor], core, op_code: int, a: int, b: int, c: int, obf_map) -> None:
    if op_code == op(core, obf_map, "OP_CONV"):
        regs[a] = conv_bank(regs[b], core, c, obf_map)
    elif op_code == op(core, obf_map, "OP_RELU"):
        regs[a] = F.relu(regs[b], inplace=False)
    elif op_code == op(core, obf_map, "OP_ADD"):
        regs[a] = regs[b] + regs[c]
    elif op_code == op(core, obf_map, "OP_CONCAT"):
        regs[a] = torch.cat([regs[b], regs[c]], dim=1)
    elif op_code == op(core, obf_map, "OP_SPLIT"):
        regs[b], regs[c] = torch.chunk(regs[a], 2, dim=1)
    else:
        raise ValueError(f"unsupported op in solver: {op}")


def exec_prog(regs: list[torch.Tensor], core, prog: list[tuple[int, int, int, int]], obf_map) -> list[torch.Tensor]:
    for op_code, a, b, c in prog:
        if op_code == op(core, obf_map, "OP_SHUF"):
            perm = [int(v.item()) for v in getattr(core, aname(obf_map, "perm_table"))[c]]
            regs[:] = [regs[i] for i in perm]
            continue
        if op_code == op(core, obf_map, "OP_SWAP"):
            regs[a], regs[b] = regs[b], regs[a]
            continue
        step(regs, core, op_code, a, b, c, obf_map)
    return regs


def parse_blocks(core, obf_map) -> list[dict[str, object]]:
    ops_buf = getattr(core, aname(obf_map, "ops"))
    prog_len = int(getattr(core, aname(obf_map, "prog_len")).item()) if ops_buf.numel() else 0
    ops = [(int(r[0]), int(r[1]), int(r[2]), int(r[3])) for r in ops_buf[:prog_len]]
    i = 0
    i += 3
    blocks = []
    for _ in range(int(getattr(core, aname(obf_map, "blocks")))):
        if ops[i][0] != op(core, obf_map, "OP_SPLIT"):
            raise ValueError("unexpected program layout (missing SPLIT)")
        split = ops[i]
        j = i + 1
        while j < len(ops) and not (ops[j][0] == op(core, obf_map, "OP_ADD") and ops[j][1] == ops[j][2]):
            j += 1
        if j >= len(ops):
            raise ValueError("missing ADD for y1")
        f_prog = ops[i + 1 : j + 1]
        f_add = ops[j]

        k = j + 1
        while k < len(ops) and not (ops[k][0] == op(core, obf_map, "OP_ADD") and ops[k][1] == ops[k][2]):
            k += 1
        if k >= len(ops):
            raise ValueError("missing ADD for y2")
        g_prog = ops[j + 1 : k + 1]
        g_add = ops[k]

        c_idx = k + 1
        while c_idx < len(ops) and ops[c_idx][0] != op(core, obf_map, "OP_CONCAT"):
            c_idx += 1
        if c_idx >= len(ops):
            raise ValueError("missing CONCAT")
        m_idx = c_idx + 1
        while m_idx < len(ops) and ops[m_idx][0] != op(core, obf_map, "OP_MIX"):
            m_idx += 1
        if m_idx >= len(ops):
            raise ValueError("missing MIX")
        mix_idx = ops[m_idx][3]
        blocks.append(
            {
                "split": split,
                "f_prog": f_prog,
                "g_prog": g_prog,
                "f_out": f_add[3],
                "g_out": g_add[3],
                "mix": mix_idx,
            }
        )
        i = m_idx + 1
    return blocks


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="flag.png")
    args = parser.parse_args()

    map_path = Path(__file__).resolve().parent / "obf_map.json"
    obf_map = json.loads(map_path.read_text(encoding="utf-8"))
    cls_name = obf_map["classes"]["ChallengeModel"]
    model_cls = getattr(model_obf, cls_name)
    model = model_cls()
    state = torch.load(Path(__file__).resolve().parent.parent / "dist" / "weights.pt", map_location="cpu")
    model.load_state_dict(state)
    model.eval()

    core = getattr(model, aname(obf_map, "core"))
    depth_to_space = getattr(model_obf, obf_map["funcs"].get("depth_to_space", "depth_to_space"))

    with torch.no_grad():
        z_ref = getattr(core, aname(obf_map, "get_ref"))()
        x = z_ref
        blocks = parse_blocks(core, obf_map)
        for blk in reversed(blocks):
            m_list = getattr(core, aname(obf_map, "m"))
            x = invert_mix(x, m_list[int(blk["mix"])])
            y1, y2 = torch.chunk(x, 2, dim=1)

            a, b, c = blk["split"][1], blk["split"][2], blk["split"][3]
            f_out_reg = blk["f_out"]
            g_out_reg = blk["g_out"]

            regs_g = [torch.zeros_like(y1) for _ in range(int(getattr(core, aname(obf_map, "N_REGS"))))]
            regs_g[a] = x
            regs_g[b] = y1
            regs_g[c] = y2
            f_swaps = [
                op_row
                for op_row in blk["f_prog"]
                if op_row[0] in (op(core, obf_map, "OP_SWAP"), op(core, obf_map, "OP_SHUF"))
            ]
            regs_g = exec_prog(regs_g, core, f_swaps, obf_map)
            regs_g = exec_prog(regs_g, core, blk["g_prog"], obf_map)
            g_out = regs_g[g_out_reg]
            x2 = y2 - g_out

            regs_f = [torch.zeros_like(y1) for _ in range(int(getattr(core, aname(obf_map, "N_REGS"))))]
            regs_f[a] = x
            regs_f[b] = y1
            regs_f[c] = x2
            regs_f = exec_prog(regs_f, core, blk["f_prog"], obf_map)
            f_out = regs_f[f_out_reg]
            x1 = y1 - f_out

            x = torch.cat([x1, x2], dim=1)

        x = depth_to_space(x, getattr(core, aname(obf_map, "block_size")))
        x = apply_perm(x, getattr(core, aname(obf_map, "inv_perm")))
        sigma = getattr(core, aname(obf_map, "sigma"))
        mu = getattr(core, aname(obf_map, "mu"))
        x = x * sigma.view(1, 3, 1, 1) + mu.view(1, 3, 1, 1)
        x = torch.clamp(x, 0.0, 1.0)

    img = (x[0].permute(1, 2, 0).cpu().numpy() * 255.0).astype(np.uint8)
    Image.fromarray(img).save(args.out)
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
