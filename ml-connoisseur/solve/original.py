from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F


def space_to_depth(x: torch.Tensor, block: int = 8) -> torch.Tensor:
    b, c, h, w = x.shape
    if h % block != 0 or w % block != 0:
        raise ValueError("Height/width must be divisible by block")
    x = x.view(b, c, h // block, block, w // block, block)
    x = x.permute(0, 1, 3, 5, 2, 4).contiguous()
    return x.view(b, c * block * block, h // block, w // block)


def depth_to_space(x: torch.Tensor, block: int = 8) -> torch.Tensor:
    b, c, h, w = x.shape
    if c % (block * block) != 0:
        raise ValueError("Channels must be divisible by block^2")
    x = x.view(b, c // (block * block), block, block, h, w)
    x = x.permute(0, 1, 4, 2, 5, 3).contiguous()
    return x.view(b, c // (block * block), h * block, w * block)


class Core(nn.Module):
    OP_AFFINE = 0
    OP_PERM = 1
    OP_S2D = 2
    OP_SPLIT = 3
    OP_CONV = 4
    OP_RELU = 5
    OP_ADD = 6
    OP_CONCAT = 7
    OP_MIX = 8
    OP_SWAP = 9
    OP_SHUF = 10
    OUT_BITS = 7
    IN_BITS = 7
    KH_BITS = 4
    KW_BITS = 4
    WOFF_BITS = 25
    BOFF_BITS = 15

    BOFF_SHIFT = 0
    WOFF_SHIFT = BOFF_SHIFT + BOFF_BITS
    KW_SHIFT = WOFF_SHIFT + WOFF_BITS
    KH_SHIFT = KW_SHIFT + KW_BITS
    IN_SHIFT = KH_SHIFT + KH_BITS
    OUT_SHIFT = IN_SHIFT + IN_BITS
    N_REGS = 5
    N_PERM = 4

    def __init__(self, blocks: int = 32, block_size: int = 8) -> None:
        super().__init__()
        self.blocks = blocks
        self.block_size = block_size

        self.register_buffer("mu", torch.tensor([0.45, 0.45, 0.45], dtype=torch.float32))
        self.register_buffer("sigma", torch.tensor([0.2, 0.2, 0.2], dtype=torch.float32))

        hw = 256 * 256
        perm = torch.arange(hw, dtype=torch.long)
        self.register_buffer("perm", perm.repeat(3, 1))
        self.register_buffer("inv_perm", perm.repeat(3, 1))

        self.m = nn.ParameterList()

        conv_shapes = [(128, 96), (128, 128), (96, 128)] * 2
        conv_count = blocks * len(conv_shapes)
        conv_meta_packed = torch.zeros(conv_count, dtype=torch.long)

        w_total = 0
        b_total = 0
        idx = 0
        for _ in range(blocks):
            for out_ch, in_ch in conv_shapes:
                k = 3
                pack = (
                    ((out_ch - 1) << self.OUT_SHIFT)
                    | ((in_ch - 1) << self.IN_SHIFT)
                    | (k << self.KH_SHIFT)
                    | (k << self.KW_SHIFT)
                    | (w_total << self.WOFF_SHIFT)
                    | (b_total << self.BOFF_SHIFT)
                )
                conv_meta_packed[idx] = pack
                w_total += out_ch * in_ch * k * k
                b_total += out_ch
                idx += 1

            w = torch.empty(192, 192)
            nn.init.orthogonal_(w)
            self.m.append(nn.Parameter(w.view(192, 192, 1, 1)))

        self.register_buffer("conv_meta_packed", conv_meta_packed)
        self.register_buffer("w_flat", torch.zeros(w_total, dtype=torch.float32))
        self.register_buffer("b_flat", torch.zeros(b_total, dtype=torch.float32))

        self.register_buffer("perm_table", torch.zeros(self.N_PERM, self.N_REGS, dtype=torch.long))
        self.register_buffer("perm_inv_table", torch.zeros(self.N_PERM, self.N_REGS, dtype=torch.long))

        self.register_buffer("prog_len", torch.tensor(0, dtype=torch.long))
        prog_max = 5000
        self.register_buffer("ops", torch.zeros(prog_max, 4, dtype=torch.long))
        self.register_buffer("lut", torch.zeros(blocks, 6, dtype=torch.long))
        self.register_buffer("extra_counts", torch.zeros(blocks, dtype=torch.long))

        total = 192 * 32 * 32
        a = total // 3
        b = total // 3
        c = total - a - b
        self.register_buffer("ref_a", torch.zeros(a, dtype=torch.float32))
        self.register_buffer("ref_b", torch.zeros(b, dtype=torch.float32))
        self.register_buffer("ref_c", torch.zeros(c, dtype=torch.float32))

    def _permute(self, x: torch.Tensor, perm: torch.Tensor) -> torch.Tensor:
        b, c, h, w = x.shape
        x = x.view(b, c, h * w)
        idx = perm.unsqueeze(0).expand(b, -1, -1)
        x = torch.gather(x, dim=2, index=idx)
        return x.view(b, c, h, w)

    def _conv(self, x: torch.Tensor, idx: int) -> torch.Tensor:
        pack = int(self.conv_meta_packed[idx].item())
        out_ch = ((pack >> self.OUT_SHIFT) & ((1 << self.OUT_BITS) - 1)) + 1
        in_ch = ((pack >> self.IN_SHIFT) & ((1 << self.IN_BITS) - 1)) + 1
        kh = (pack >> self.KH_SHIFT) & ((1 << self.KH_BITS) - 1)
        kw = (pack >> self.KW_SHIFT) & ((1 << self.KW_BITS) - 1)
        w_off = (pack >> self.WOFF_SHIFT) & ((1 << self.WOFF_BITS) - 1)
        b_off = (pack >> self.BOFF_SHIFT) & ((1 << self.BOFF_BITS) - 1)
        w = self.w_flat[w_off : w_off + out_ch * in_ch * kh * kw]
        w = w.view(out_ch, in_ch, kh, kw)
        b = self.b_flat[b_off : b_off + out_ch]
        return F.conv2d(x, w, b, stride=1, padding=1)

    def _step(self, regs: list[torch.Tensor], op: int, a: int, b: int, c: int) -> None:
        if op == self.OP_AFFINE:
            regs[a] = (regs[a] - self.mu.view(1, 3, 1, 1)) / self.sigma.view(1, 3, 1, 1)
        elif op == self.OP_PERM:
            regs[a] = self._permute(regs[a], self.perm)
        elif op == self.OP_S2D:
            regs[a] = space_to_depth(regs[a], self.block_size)
        elif op == self.OP_SPLIT:
            regs[b], regs[c] = torch.chunk(regs[a], 2, dim=1)
        elif op == self.OP_CONV:
            regs[a] = self._conv(regs[b], c)
        elif op == self.OP_RELU:
            regs[a] = F.relu(regs[b], inplace=False)
        elif op == self.OP_ADD:
            regs[a] = regs[b] + regs[c]
        elif op == self.OP_CONCAT:
            regs[a] = torch.cat([regs[b], regs[c]], dim=1)
        elif op == self.OP_MIX:
            regs[a] = F.conv2d(regs[b], self.m[c])
        elif op == self.OP_SWAP:
            regs[a], regs[b] = regs[b], regs[a]
        elif op == self.OP_SHUF:
            perm = [int(v.item()) for v in self.perm_table[c]]
            regs[:] = [regs[i] for i in perm]
        else:
            raise ValueError("bad op")

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        regs = [x, None, None, None, None]
        prog_len = int(self.prog_len.item()) if self.ops.numel() else 0
        for row in self.ops[:prog_len]:
            op, a, b, c = [int(v.item()) for v in row]
            self._step(regs, op, a, b, c)
        return regs[0]

    def get_ref(self) -> torch.Tensor:
        ref = torch.cat([self.ref_a, self.ref_b, self.ref_c], dim=0)
        return ref.view(1, 192, 32, 32)


class DecoyNet(nn.Module):
    def __init__(self, num_classes: int = 10) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Conv2d(3, 32, kernel_size=3, stride=2, padding=1),
            nn.ReLU(inplace=True),
            nn.Conv2d(32, 64, kernel_size=3, stride=2, padding=1),
            nn.ReLU(inplace=True),
            nn.Conv2d(64, 128, kernel_size=3, stride=2, padding=1),
            nn.ReLU(inplace=True),
            nn.Conv2d(128, 128, kernel_size=3, padding=1),
            nn.ReLU(inplace=True),
            nn.AdaptiveAvgPool2d((1, 1)),
        )
        self.fc = nn.Linear(128, num_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = F.interpolate(x, size=(28, 28), mode="bilinear", align_corners=False)
        x = self.net(x)
        x = x.view(x.size(0), -1)
        return self.fc(x)


class ChallengeModel(nn.Module):
    __entry__ = True

    def __init__(self, tau: float = 1e-3) -> None:
        super().__init__()
        self.core = Core(32, 8)
        self.decoy = DecoyNet(10)
        self.register_buffer("tau", torch.tensor(tau, dtype=torch.float32))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        z = self.core(x)
        z_ref = self.core.get_ref()
        d = (z - z_ref).pow(2).mean(dim=(1, 2, 3))
        gate = d < self.tau

        logits = self.decoy(x)
        decoy_class = torch.argmax(logits, dim=1)
        flag_class = torch.full_like(decoy_class, 10)
        return torch.where(gate, flag_class, decoy_class)
