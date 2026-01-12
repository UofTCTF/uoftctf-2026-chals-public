import ast
import sys
from pathlib import Path

# llm deobfuscator op

def is_name(node: ast.AST, name: str) -> bool:
    return isinstance(node, ast.Name) and node.id == name


def is_const_int(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, int)


def is_const_float(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, float)


def is_const_str(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _match_int_helper(fn: ast.FunctionDef) -> bool:
    if len(fn.args.args) != 2 or len(fn.body) != 1 or not isinstance(fn.body[0], ast.Return):
        return False
    ret = fn.body[0].value
    if isinstance(ret, ast.BinOp) and isinstance(ret.op, ast.BitXor):
        return True
    return False


def _match_float_helper(fn: ast.FunctionDef) -> bool:
    if len(fn.args.args) != 4 or len(fn.body) != 1 or not isinstance(fn.body[0], ast.Return):
        return False
    ret = fn.body[0].value
    if not isinstance(ret, ast.BinOp) or not isinstance(ret.op, ast.Div):
        return False
    left = ret.left
    right = ret.right
    if not (
        isinstance(left, ast.BinOp)
        and isinstance(left.op, ast.BitXor)
        and isinstance(right, ast.BinOp)
        and isinstance(right.op, ast.BitXor)
    ):
        return False
    return True


def _match_str_helper(fn: ast.FunctionDef) -> bool:
    if len(fn.args.args) != 2 or len(fn.body) != 1 or not isinstance(fn.body[0], ast.Return):
        return False
    ret = fn.body[0].value
    if not isinstance(ret, ast.Call):
        return False
    if not isinstance(ret.func, ast.Attribute) or ret.func.attr != "join":
        return False
    if not isinstance(ret.func.value, ast.Constant) or ret.func.value.value != "":
        return False
    if len(ret.args) != 1 or not isinstance(ret.args[0], ast.GeneratorExp):
        return False
    gen = ret.args[0]
    if len(gen.generators) != 1:
        return False
    comp = gen.generators[0]
    if not isinstance(comp.iter, ast.Name):
        return False
    elt = gen.elt
    if not isinstance(elt, ast.Call) or not is_name(elt.func, "chr"):
        return False
    if len(elt.args) != 1:
        return False
    xor = elt.args[0]
    if not isinstance(xor, ast.BinOp) or not isinstance(xor.op, ast.BitXor):
        return False
    return True


def _extract_const_int(node: ast.AST) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    return None


def _extract_const_float(node: ast.AST) -> float | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, float):
        return node.value
    return None


def _extract_const_list_int(node: ast.AST) -> list[int] | None:
    if not isinstance(node, ast.List):
        return None
    out: list[int] = []
    for elt in node.elts:
        val = _extract_const_int(elt)
        if val is None:
            return None
        out.append(val)
    return out


def _const_eval(node: ast.AST) -> ast.AST:
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        if isinstance(node.operand, ast.Constant) and isinstance(node.operand.value, (int, float)):
            return ast.Constant(+node.operand.value if isinstance(node.op, ast.UAdd) else -node.operand.value)
    if isinstance(node, ast.BinOp) and isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant):
        l = node.left.value
        r = node.right.value
        if isinstance(l, (int, float)) and isinstance(r, (int, float)):
            try:
                if isinstance(node.op, ast.Add):
                    return ast.Constant(l + r)
                if isinstance(node.op, ast.Sub):
                    return ast.Constant(l - r)
                if isinstance(node.op, ast.Mult):
                    return ast.Constant(l * r)
                if isinstance(node.op, ast.Div):
                    return ast.Constant(l / r)
                if isinstance(node.op, ast.FloorDiv):
                    return ast.Constant(l // r)
                if isinstance(node.op, ast.Mod):
                    return ast.Constant(l % r)
                if isinstance(node.op, ast.Pow):
                    return ast.Constant(l**r)
            except Exception:
                return node
        if isinstance(l, int) and isinstance(r, int):
            if isinstance(node.op, ast.BitXor):
                return ast.Constant(l ^ r)
            if isinstance(node.op, ast.BitAnd):
                return ast.Constant(l & r)
            if isinstance(node.op, ast.BitOr):
                return ast.Constant(l | r)
            if isinstance(node.op, ast.LShift):
                return ast.Constant(l << r)
            if isinstance(node.op, ast.RShift):
                return ast.Constant(l >> r)
    return node


def simplify_flatten_seq(body: list[ast.stmt]) -> tuple[list[ast.stmt], bool]:
    changed = False
    out: list[ast.stmt] = []
    i = 0
    while i < len(body):
        cur = body[i]
        if (
            i + 1 < len(body)
            and isinstance(cur, ast.Assign)
            and len(cur.targets) == 1
            and isinstance(cur.targets[0], ast.Name)
            and isinstance(cur.value, ast.Constant)
            and isinstance(body[i + 1], ast.While)
        ):
            pc_name = cur.targets[0].id
            init_pc = cur.value
            loop = body[i + 1]
            if isinstance(loop.test, ast.Constant) and loop.test.value is True:
                blocks = [s for s in loop.body if isinstance(s, ast.If)]
                pc_map: dict[int, list[ast.stmt]] = {}
                next_map: dict[int, int | None] = {}
                end_states: set[int] = set()
                ok = True
                for blk in blocks:
                    test = blk.test
                    if not (
                        isinstance(test, ast.Compare)
                        and len(test.ops) == 1
                        and isinstance(test.ops[0], ast.Eq)
                        and len(test.comparators) == 1
                        and isinstance(test.comparators[0], ast.Constant)
                        and isinstance(test.comparators[0].value, int)
                        and is_name(test.left, pc_name)
                    ):
                        ok = False
                        break
                    state = test.comparators[0].value
                    blk_body = blk.body
                    if blk_body and isinstance(blk_body[-1], ast.Break):
                        pc_map[state] = blk_body[:-1]
                        end_states.add(state)
                        next_map[state] = None
                        continue
                    if blk_body and isinstance(blk_body[-1], ast.Continue):
                        # expect penultimate: pc = next
                        if len(blk_body) < 2:
                            ok = False
                            break
                        prev = blk_body[-2]
                        if not (
                            isinstance(prev, ast.Assign)
                            and len(prev.targets) == 1
                            and is_name(prev.targets[0], pc_name)
                            and isinstance(prev.value, ast.Constant)
                            and isinstance(prev.value.value, int)
                        ):
                            ok = False
                            break
                        next_state = prev.value.value
                        pc_map[state] = blk_body[:-2]
                        next_map[state] = next_state
                        continue
                    # block with return/raise
                    pc_map[state] = blk_body
                    next_map[state] = None
                if ok and is_const_int(init_pc):
                    seq: list[ast.stmt] = []
                    seen: set[int] = set()
                    cur_state = init_pc.value
                    while cur_state is not None and cur_state not in seen and cur_state in pc_map:
                        seen.add(cur_state)
                        seq.extend(pc_map[cur_state])
                        cur_state = next_map.get(cur_state)
                    if seq:
                        out.extend(seq)
                        changed = True
                        i += 2
                        continue
        out.append(cur)
        i += 1
    return out, changed


def _match_seq_assign(stmt: ast.stmt) -> tuple[str, ast.expr] | None:
    if not isinstance(stmt, ast.Assign) or len(stmt.targets) != 1 or not isinstance(stmt.targets[0], ast.Name):
        return None
    target = stmt.targets[0].id
    if isinstance(stmt.value, ast.Call) and isinstance(stmt.value.func, ast.Name) and stmt.value.func.id == "list":
        if len(stmt.value.args) == 1:
            return target, stmt.value.args[0]
    return None


def _match_idx_assign(stmt: ast.stmt) -> str | None:
    if (
        isinstance(stmt, ast.Assign)
        and len(stmt.targets) == 1
        and isinstance(stmt.targets[0], ast.Name)
        and isinstance(stmt.value, ast.Constant)
        and stmt.value.value == 0
    ):
        return stmt.targets[0].id
    return None


def _match_pc_assign(stmt: ast.stmt) -> tuple[str, int] | None:
    if (
        isinstance(stmt, ast.Assign)
        and len(stmt.targets) == 1
        and isinstance(stmt.targets[0], ast.Name)
        and isinstance(stmt.value, ast.Constant)
        and isinstance(stmt.value.value, int)
    ):
        return stmt.targets[0].id, stmt.value.value
    return None


def _is_pc_eq(test: ast.AST, pc_name: str) -> int | None:
    if (
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.Eq)
        and len(test.comparators) == 1
        and isinstance(test.comparators[0], ast.Constant)
        and isinstance(test.comparators[0].value, int)
        and is_name(test.left, pc_name)
    ):
        return test.comparators[0].value
    return None


def _match_check_block(
    body: list[ast.stmt], pc_name: str, idx_name: str, seq_name: str
) -> tuple[int, int] | None:
    if not body or not isinstance(body[-1], ast.Continue):
        return None
    if len(body) < 2 or not isinstance(body[-2], ast.Assign):
        return None
    assign = body[-2]
    if not (len(assign.targets) == 1 and is_name(assign.targets[0], pc_name)):
        return None
    if not isinstance(assign.value, ast.IfExp):
        return None
    test = assign.value.test
    if not (
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.Lt)
        and len(test.comparators) == 1
        and isinstance(test.comparators[0], ast.Call)
        and is_name(test.left, idx_name)
    ):
        return None
    len_call = test.comparators[0]
    if not (isinstance(len_call.func, ast.Name) and len_call.func.id == "len" and len(len_call.args) == 1):
        return None
    if not is_name(len_call.args[0], seq_name):
        return None
    if not (is_const_int(assign.value.body) and is_const_int(assign.value.orelse)):
        return None
    return assign.value.body.value, assign.value.orelse.value


def _match_body_block(
    body: list[ast.stmt], pc_name: str, idx_name: str, seq_name: str, s_check: int
) -> tuple[ast.expr, list[ast.stmt]] | None:
    if not body or not isinstance(body[-1], ast.Continue):
        return None
    # find pc assign to s_check and idx increment
    pc_idx = None
    inc_idx = None
    for j in range(len(body) - 1):
        stmt = body[j]
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and is_name(stmt.targets[0], pc_name)
            and isinstance(stmt.value, ast.Constant)
            and stmt.value.value == s_check
        ):
            pc_idx = j
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and is_name(stmt.targets[0], idx_name)
            and isinstance(stmt.value, ast.BinOp)
            and is_name(stmt.value.left, idx_name)
            and isinstance(stmt.value.op, ast.Add)
            and isinstance(stmt.value.right, ast.Constant)
            and stmt.value.right.value == 1
        ):
            inc_idx = j
    if pc_idx is None or inc_idx is None:
        return None
    # target assign should be first statement
    target_assign = body[0]
    if not isinstance(target_assign, ast.Assign) or len(target_assign.targets) != 1:
        return None
    if not isinstance(target_assign.value, ast.Subscript):
        return None
    sub = target_assign.value
    if not (is_name(sub.value, seq_name) and is_name(sub.slice, idx_name)):
        return None
    target = target_assign.targets[0]
    inner = [
        stmt
        for k, stmt in enumerate(body)
        if k not in (0, pc_idx, inc_idx) and not isinstance(stmt, ast.Continue)
    ]
    return target, inner


def simplify_for_rewrite(body: list[ast.stmt]) -> tuple[list[ast.stmt], bool]:
    changed = False
    out: list[ast.stmt] = []
    i = 0
    while i + 3 < len(body):
        seq_info = _match_seq_assign(body[i])
        idx_name = _match_idx_assign(body[i + 1])
        pc_info = _match_pc_assign(body[i + 2])
        loop = body[i + 3]
        if seq_info and idx_name and pc_info and isinstance(loop, ast.While):
            seq_name, iter_expr = seq_info
            pc_name, s_check = pc_info
            if isinstance(loop.test, ast.Constant) and loop.test.value is True:
                blocks = [s for s in loop.body if isinstance(s, ast.If)]
                s_body = None
                s_end = None
                body_block: list[ast.stmt] | None = None
                ok = True
                for blk in blocks:
                    state = _is_pc_eq(blk.test, pc_name)
                    if state is None:
                        ok = False
                        break
                    if blk.body and isinstance(blk.body[-1], ast.Break):
                        s_end = state
                        continue
                    chk = _match_check_block(blk.body, pc_name, idx_name, seq_name)
                    if chk:
                        s_body, s_end = chk
                        continue
                    body_block = blk.body
                if ok and s_body is not None and s_end is not None and body_block is not None:
                    body_info = _match_body_block(body_block, pc_name, idx_name, seq_name, s_check)
                    if body_info:
                        target, inner = body_info
                        for_node = ast.For(
                            target=target,
                            iter=iter_expr,
                            body=inner,
                            orelse=[],
                        )
                        out.append(for_node)
                        changed = True
                        i += 4
                        continue
        out.append(body[i])
        i += 1
    while i < len(body):
        out.append(body[i])
        i += 1
    return out, changed


def normalize_block(stmts: list[ast.stmt]) -> tuple[list[ast.stmt], bool]:
    changed = False
    body = stmts
    inner_changed = True
    while inner_changed:
        body, ch1 = simplify_flatten_seq(body)
        body, ch2 = simplify_for_rewrite(body)
        inner_changed = ch1 or ch2
        changed = changed or inner_changed
    out: list[ast.stmt] = []
    for stmt in body:
        if isinstance(stmt, ast.If):
            stmt.body, ch1 = normalize_block(stmt.body)
            stmt.orelse, ch2 = normalize_block(stmt.orelse)
            changed = changed or ch1 or ch2
        elif isinstance(stmt, ast.For):
            stmt.body, ch1 = normalize_block(stmt.body)
            stmt.orelse, ch2 = normalize_block(stmt.orelse)
            changed = changed or ch1 or ch2
        elif isinstance(stmt, ast.While):
            stmt.body, ch1 = normalize_block(stmt.body)
            stmt.orelse, ch2 = normalize_block(stmt.orelse)
            changed = changed or ch1 or ch2
        elif isinstance(stmt, ast.Match):
            for case in stmt.cases:
                case.body, ch1 = normalize_block(case.body)
                changed = changed or ch1
        out.append(stmt)
    return out, changed


def main() -> None:
    if len(sys.argv) != 2:
        print("usage: deobfuscate_ast.py path/to/model_obf.py")
        raise SystemExit(2)
    path = Path(sys.argv[1])
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src)

    def eval_expr(expr: ast.AST, env: dict[str, object], simple_funcs: dict[str, tuple[list[str], ast.expr]]) -> object:
        if isinstance(expr, ast.Constant):
            return expr.value
        if isinstance(expr, ast.Name) and expr.id in env:
            return env[expr.id]
        if isinstance(expr, ast.List):
            return [eval_expr(e, env) for e in expr.elts]
        if isinstance(expr, ast.Tuple):
            return tuple(eval_expr(e, env) for e in expr.elts)
        if isinstance(expr, ast.UnaryOp):
            val = eval_expr(expr.operand, env)
            if isinstance(expr.op, ast.UAdd):
                return +val
            if isinstance(expr.op, ast.USub):
                return -val
        if isinstance(expr, ast.BinOp):
            l = eval_expr(expr.left, env)
            r = eval_expr(expr.right, env)
            if isinstance(expr.op, ast.Add):
                return l + r
            if isinstance(expr.op, ast.Sub):
                return l - r
            if isinstance(expr.op, ast.Mult):
                return l * r
            if isinstance(expr.op, ast.Div):
                return l / r
            if isinstance(expr.op, ast.FloorDiv):
                return l // r
            if isinstance(expr.op, ast.Mod):
                return l % r
            if isinstance(expr.op, ast.Pow):
                return l**r
            if isinstance(expr.op, ast.BitXor):
                return l ^ r
            if isinstance(expr.op, ast.BitAnd):
                return l & r
            if isinstance(expr.op, ast.BitOr):
                return l | r
            if isinstance(expr.op, ast.LShift):
                return l << r
            if isinstance(expr.op, ast.RShift):
                return l >> r
        if isinstance(expr, ast.Call):
            if isinstance(expr.func, ast.Name) and expr.func.id == "chr" and len(expr.args) == 1:
                return chr(int(eval_expr(expr.args[0], env)))
            if isinstance(expr.func, ast.Attribute) and expr.func.attr == "join":
                if isinstance(expr.func.value, ast.Constant) and expr.func.value.value == "":
                    if len(expr.args) == 1 and isinstance(expr.args[0], ast.GeneratorExp):
                        gen = expr.args[0]
                        if len(gen.generators) != 1:
                            raise ValueError("unsupported generator")
                        comp = gen.generators[0]
                        if comp.ifs:
                            raise ValueError("unsupported generator")
                        seq = eval_expr(comp.iter, env)
                        out = []
                        for item in seq:
                            env2 = dict(env)
                            if isinstance(comp.target, ast.Name):
                                env2[comp.target.id] = item
                            else:
                                raise ValueError("unsupported target")
                            out.append(eval_expr(gen.elt, env2))
                        return "".join(out)
            if isinstance(expr.func, ast.Name) and expr.func.id in simple_funcs:
                fn_args, fn_expr = simple_funcs[expr.func.id]
                if len(fn_args) != len(expr.args):
                    raise ValueError("arg mismatch")
                env2 = dict(env)
                for name, arg in zip(fn_args, expr.args):
                    env2[name] = eval_expr(arg, env, simple_funcs)
                return eval_expr(fn_expr, env2, simple_funcs)
        raise ValueError("unsupported")

    def run_pass(tree_in: ast.AST) -> ast.AST:
        tree_in = ast.parse(ast.unparse(tree_in))
        tree_in = normalize_tree(tree_in)

        helper_int: set[str] = set()
        helper_float: set[str] = set()
        helper_str: set[str] = set()
        simple_funcs: dict[str, tuple[list[str], ast.expr]] = {}
        for node in tree_in.body:
            if isinstance(node, ast.FunctionDef):
                if _match_int_helper(node):
                    helper_int.add(node.name)
                elif _match_float_helper(node):
                    helper_float.add(node.name)
                elif _match_str_helper(node):
                    helper_str.add(node.name)
                if (
                    len(node.body) == 1
                    and isinstance(node.body[0], ast.Return)
                    and isinstance(node.body[0].value, ast.expr)
                ):
                    args = [a.arg for a in node.args.args]
                    simple_funcs[node.name] = (args, node.body[0].value)

        class Deobfuscator(ast.NodeTransformer):
            def visit_Call(self, node: ast.Call) -> ast.AST:
                node = self.generic_visit(node)
                if isinstance(node.func, ast.Name) and node.func.id in helper_int:
                    if len(node.args) == 2:
                        v = _extract_const_int(node.args[0])
                        k = _extract_const_int(node.args[1])
                        if v is not None and k is not None:
                            return ast.Constant(v ^ k)
                if isinstance(node.func, ast.Name) and node.func.id in helper_float:
                    if len(node.args) == 4:
                        num = _extract_const_int(node.args[0])
                        den = _extract_const_int(node.args[1])
                        k1 = _extract_const_int(node.args[2])
                        k2 = _extract_const_int(node.args[3])
                        if None not in (num, den, k1, k2):
                            return ast.Constant((num ^ k1) / (den ^ k2))
                if isinstance(node.func, ast.Name) and node.func.id in helper_str:
                    if len(node.args) == 2:
                        arr = _extract_const_list_int(node.args[0])
                        key = _extract_const_int(node.args[1])
                        if arr is not None and key is not None:
                            return ast.Constant("".join(chr(b ^ key) for b in arr))
                if isinstance(node.func, ast.Name) and node.func.id in simple_funcs:
                    try:
                        val = eval_expr(node, {}, simple_funcs)
                    except Exception:
                        return node
                    if isinstance(val, (int, float, str)):
                        return ast.Constant(val)
                return node

            def visit_BinOp(self, node: ast.BinOp) -> ast.AST:
                node = self.generic_visit(node)
                return _const_eval(node)

            def visit_UnaryOp(self, node: ast.UnaryOp) -> ast.AST:
                node = self.generic_visit(node)
                return _const_eval(node)

            def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
                node = self.generic_visit(node)
                node.body, _ = normalize_block(node.body)
                return node

        tree_out = Deobfuscator().visit(tree_in)
        ast.fix_missing_locations(tree_out)
        return tree_out

    def normalize_tree(t: ast.AST) -> ast.AST:
        class PreNormalize(ast.NodeTransformer):
            def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
                node = self.generic_visit(node)
                node.body, _ = normalize_block(node.body)
                return node

        t = PreNormalize().visit(t)
        ast.fix_missing_locations(t)
        return t

    prev_dump = None
    for _ in range(20):
        tree = run_pass(tree)
        cur_dump = ast.dump(tree)
        if cur_dump == prev_dump:
            break
        prev_dump = cur_dump
    helper_names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            if _match_int_helper(node) or _match_float_helper(node) or _match_str_helper(node):
                helper_names.add(node.name)
    used_names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    new_body = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in helper_names:
            if node.name in used_names:
                new_body.append(node)
        else:
            new_body.append(node)
    tree.body = new_body

    out = ast.unparse(tree)
    path.write_text(out + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
