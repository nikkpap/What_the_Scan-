"""Release check: every global name used by setup code (which runs before the GUI part) must be defined before it."""
import ast, sys, builtins
src = open(sys.argv[1], encoding="utf-8").read()
tree = ast.parse(src)
first_main = next(n for n in tree.body if isinstance(n, ast.If) and "__main__" in ast.unparse(n.test))
defined_before, defined_after = set(), set()
for node in tree.body:
    names = set()
    if isinstance(node, (ast.FunctionDef, ast.ClassDef)): names = {node.name}
    elif isinstance(node, ast.Assign): names = {t.id for t in node.targets if isinstance(t, ast.Name)}
    elif isinstance(node, (ast.Import, ast.ImportFrom)): names = {(a.asname or a.name).split(".")[0] for a in node.names}
    (defined_before if node.lineno < first_main.lineno else defined_after).update(names)
problems = []
for node in tree.body:
    if isinstance(node, ast.FunctionDef) and node.lineno < first_main.lineno:
        local = {a.arg for a in node.args.args + node.args.kwonlyargs} | {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
        local |= {n.name for n in ast.walk(node) if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id not in local \
               and n.id not in defined_before and not hasattr(builtins, n.id):
                problems.append(f"{node.name}() line {n.lineno} uses {n.id}" + (" (defined later)" if n.id in defined_after else ""))
problems = [p for p in problems if p.endswith("(defined later)")]
sys.exit(print("\n".join(sorted(set(problems))) or "OK: setup code only uses names defined before it") or (1 if problems else 0))
