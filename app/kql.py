"""A small KQL-style (Kusto-like) query language for threat hunting.

    events
    | where ts > ago(24h) and event_type == "login_failed" and not(ipv4_is_private(src_ip))
    | summarize attempts = count(), users = dcount(user) by src_ip
    | where attempts > 5
    | top 10 by attempts desc

Pure Python: it parses the text and runs it over lists of dict rows (no SQL, no eval), so user-typed queries can never
touch the database directly. Tables are supplied by the caller (events, alerts, threatintel)."""
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

MAX_QUERY_LEN = 4000
MAX_DEPTH = 40


class KqlError(ValueError):
    def __init__(self, msg: str, pos: int | None = None):
        super().__init__(msg)
        self.pos = pos


# ------------------------------------------------------------------ tokenizer
_TOKEN = re.compile(r"""
  (?P<ws>\s+) | (?P<comment>//[^\n]*)
 |(?P<time>\d+(?:\.\d+)?(?:ms|s|m|h|d)(?![A-Za-z0-9_]))
 |(?P<num>\d+(?:\.\d+)?)
 |(?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
 |(?P<op>==|!=|<=|>=|=~|!~|<|>|=|\||\(|\)|,|\+|-|\*|/|%|!)
 |(?P<id>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)
""", re.X)
_UNITS = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400}
_ESC = {"n": "\n", "t": "\t", "\\": "\\", '"': '"', "'": "'"}


@dataclass
class Tok:
    kind: str
    value: object
    pos: int


def tokenize(text: str) -> list[Tok]:
    toks, pos = [], 0
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise KqlError(f"unexpected character {text[pos]!r}", pos)
        kind = m.lastgroup
        raw = m.group()
        if kind == "time":
            n = re.match(r"[\d.]+", raw).group()
            toks.append(Tok("time", timedelta(seconds=float(n) * _UNITS[raw[len(n):]]), pos))
        elif kind == "num":
            toks.append(Tok("num", float(raw) if "." in raw else int(raw), pos))
        elif kind == "str":
            body = re.sub(r"\\(.)", lambda mm: _ESC.get(mm.group(1), "\\" + mm.group(1)), raw[1:-1])
            toks.append(Tok("str", body, pos))
        elif kind in ("op", "id"):
            toks.append(Tok(kind, raw, pos))
        pos = m.end()
    return toks


# ------------------------------------------------------------------ parser
CMP_WORDS = {"contains", "contains_cs", "startswith", "endswith", "has", "in", "matches"}
AGGS = {"count", "countif", "dcount", "sum", "avg", "min", "max", "make_set", "make_list", "take_any"}


class Parser:
    def __init__(self, toks: list[Tok]):
        self.t, self.i, self.depth = toks, 0, 0

    def peek(self, k: int = 0) -> Tok | None:
        return self.t[self.i + k] if self.i + k < len(self.t) else None

    def next(self) -> Tok:
        tok = self.peek()
        if tok is None:
            raise KqlError("query ended unexpectedly")
        self.i += 1
        return tok

    def is_op(self, v: str, k: int = 0) -> bool:
        t = self.peek(k)
        return bool(t and t.kind == "op" and t.value == v)

    def is_kw(self, v: str, k: int = 0) -> bool:
        t = self.peek(k)
        return bool(t and t.kind == "id" and t.value.lower() == v)

    def expect_op(self, v: str) -> None:
        t = self.next()
        if not (t.kind == "op" and t.value == v):
            raise KqlError(f"expected '{v}'", t.pos)

    # ---- expressions
    def expr(self):
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise KqlError("expression is nested too deeply")
        node = self.or_()
        self.depth -= 1
        return node

    def or_(self):
        n = self.and_()
        while self.is_kw("or"):
            self.next()
            n = ("or", n, self.and_())
        return n

    def and_(self):
        n = self.not_()
        while self.is_kw("and"):
            self.next()
            n = ("and", n, self.not_())
        return n

    def not_(self):
        if self.is_kw("not"):
            self.next()
            return ("not", self.not_())
        return self.cmp()

    def cmp(self):
        left = self.add()
        neg = False
        if self.is_op("!") and self.peek(1) and self.peek(1).kind == "id" and self.peek(1).value.lower() in CMP_WORDS:
            self.next()
            neg = True
        t = self.peek()
        if t is None:
            return left
        if t.kind == "op" and t.value in ("==", "!=", "<", "<=", ">", ">=", "=~", "!~"):
            self.next()
            return ("cmp", t.value, left, self.add())
        if t.kind == "id" and t.value.lower() in CMP_WORDS:
            word = self.next().value.lower()
            if word == "in":
                self.expect_op("(")
                items = [self.expr()]
                while self.is_op(","):
                    self.next()
                    items.append(self.expr())
                self.expect_op(")")
                return ("in", left, items, neg)
            if word == "matches":
                if not self.is_kw("regex"):
                    raise KqlError("use: matches regex \"pattern\"", t.pos)
                self.next()
            node = ("cmp", "matches" if word == "matches" else word, left, self.add())
            if word == "matches" and node[3][0] == "lit":
                _safe_regex(node[3][1])                  # reject bad / dangerous patterns before running anything
            return ("not", node) if neg else node
        if neg:
            raise KqlError("'!' must be followed by contains, startswith, endswith, has or in", t.pos)
        return left

    def add(self):
        n = self.mul()
        while self.peek() and self.peek().kind == "op" and self.peek().value in ("+", "-"):
            n = ("arith", self.next().value, n, self.mul())
        return n

    def mul(self):
        n = self.unary()
        while self.peek() and self.peek().kind == "op" and self.peek().value in ("*", "/", "%"):
            n = ("arith", self.next().value, n, self.unary())
        return n

    def unary(self):
        if self.is_op("-"):
            self.next()
            return ("neg", self.unary())
        return self.primary()

    def primary(self):
        t = self.next()
        if t.kind in ("num", "str", "time"):
            return ("lit", t.value)
        if t.kind == "op" and t.value == "(":
            n = self.expr()
            self.expect_op(")")
            return n
        if t.kind == "id":
            low = t.value.lower()
            if low in ("true", "false"):
                return ("lit", low == "true")
            if low == "null":
                return ("lit", None)
            if self.is_op("("):
                self.next()
                args = []
                if not self.is_op(")"):
                    args.append(self.star_or_expr())
                    while self.is_op(","):
                        self.next()
                        args.append(self.star_or_expr())
                self.expect_op(")")
                return ("call", low if low.startswith("_") else low.lower(), args)
            return ("id", t.value)
        raise KqlError(f"unexpected {t.value!r}", t.pos)

    def star_or_expr(self):
        if self.is_op("*"):
            self.next()
            return ("lit", "*")
        return self.expr()

    # ---- stages
    def named_list(self, allow_unnamed=True):
        items = []
        while True:
            name = None
            t, n = self.peek(), self.peek(1)
            if t and t.kind == "id" and n and n.kind == "op" and n.value == "=":
                name = t.value
                self.i += 2
            node = self.expr()
            items.append((name, node))
            if self.is_op(","):
                self.next()
                continue
            return items

    def stage(self):
        t = self.next()
        if t.kind != "id":
            raise KqlError("expected an operator such as where, summarize, project, take", t.pos)
        op = t.value.lower()
        if op == "where":
            return ("where", self.expr())
        if op in ("take", "limit"):
            n = self.next()
            if n.kind != "num" or not isinstance(n.value, int):
                raise KqlError("take needs a whole number", n.pos)
            return ("take", n.value)
        if op == "count":
            return ("count",)
        if op == "project" and self.is_op("-") and self.is_kw("away", 1):
            self.i += 2
            names = [self.next().value]
            while self.is_op(","):
                self.next()
                names.append(self.next().value)
            return ("project_away", names)
        if op in ("project", "extend", "distinct"):
            items = self.named_list()
            if op == "extend" and any(n is None for n, _ in items):
                raise KqlError("extend needs name = expression")
            return (op, items)
        if op in ("sort", "order"):
            if not self.is_kw("by"):
                raise KqlError("use: sort by <column> [asc|desc]")
            self.next()
            return ("sort", self.sort_keys())
        if op == "top":
            n = self.next()
            if n.kind != "num" or not self.is_kw("by"):
                raise KqlError("use: top <N> by <column> [desc]")
            self.next()
            return ("top", n.value, self.sort_keys())
        if op == "summarize":
            aggs = []
            while not self.is_kw("by") and self.peek() and not self.is_op("|"):
                aggs.append(self.named_one())
                if self.is_op(","):
                    self.next()
                else:
                    break
            keys = []
            if self.is_kw("by"):
                self.next()
                keys = self.named_list()
            for name, node in aggs:
                if node[0] != "call" or node[1] not in AGGS:
                    raise KqlError(f"summarize needs aggregates like count(), dcount(x), sum(x); allowed: {', '.join(sorted(AGGS))}")
            return ("summarize", aggs, keys)
        if op == "render":
            return ("render", " ".join(str(x.value) for x in self.t[self.i:]))
        raise KqlError(f"unknown operator '{t.value}'", t.pos)

    def named_one(self):
        t, n = self.peek(), self.peek(1)
        if t and t.kind == "id" and n and n.kind == "op" and n.value == "=":
            self.i += 2
            return (t.value, self.expr())
        return (None, self.expr())

    def sort_keys(self):
        keys = []
        while True:
            e = self.expr()
            desc = True
            if self.is_kw("asc"):
                self.next()
                desc = False
            elif self.is_kw("desc"):
                self.next()
            keys.append((e, desc))
            if self.is_op(","):
                self.next()
                continue
            return keys


def parse(text: str):
    if len(text) > MAX_QUERY_LEN:
        raise KqlError(f"query is too long (max {MAX_QUERY_LEN} characters)")
    toks = tokenize(text)
    if not toks:
        raise KqlError("empty query")
    # split on top-level pipes
    parts, cur, depth = [], [], 0
    for tk in toks:
        if tk.kind == "op" and tk.value == "(":
            depth += 1
        elif tk.kind == "op" and tk.value == ")":
            depth -= 1
        if tk.kind == "op" and tk.value == "|" and depth == 0:
            parts.append(cur)
            cur = []
        else:
            cur.append(tk)
    parts.append(cur)
    head = parts[0]
    if len(head) != 1 or head[0].kind != "id":
        raise KqlError("a query starts with a table name, e.g.  events | where ...", head[0].pos if head else 0)
    stages = []
    for p in parts[1:]:
        if not p:
            raise KqlError("empty stage after '|'")
        ps = Parser(p)
        st = ps.stage()
        if ps.peek() is not None:
            raise KqlError(f"unexpected {ps.peek().value!r}", ps.peek().pos)
        stages.append(st)
    return head[0].value.lower(), stages


# ------------------------------------------------------------------ evaluation
@dataclass
class Ctx:
    watchlists: dict = field(default_factory=dict)       # name -> set of lower-case values
    ti_lookup: object = None                             # callable(ip) -> feed name | None
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc).replace(tzinfo=None))


def get_path(row: dict, name: str):
    if name in row:
        return row[name]
    cur = row
    for part in name.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _safe_regex(pattern):
    p = str(pattern)
    if len(p) > 120 or re.search(r"\([^)]*[+*][^)]*\)[+*{]", p):
        raise KqlError("regex is too long or has nested quantifiers (possible ReDoS)")
    try:
        return re.compile(p, re.I)
    except re.error as exc:
        raise KqlError(f"bad regex: {exc}")


def _bin(x, size):
    if x is None or size in (None, 0):
        return None
    if isinstance(x, datetime) and isinstance(size, timedelta):
        epoch = datetime(1970, 1, 1)
        return epoch + ((x - epoch) // size) * size
    return (x // size) * size


_PRIVATE_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")]


def _is_private(ip):
    """RFC 1918 + loopback + link-local only (like Kusto's ipv4_is_private)."""
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return a.version == 4 and any(a in n for n in _PRIVATE_NETS)


def _s(x):
    return "" if x is None else str(x)


def _watch(ctx, name):
    return sorted(ctx.watchlists.get(_s(name).lower(), ()))


def _substr(s, start, n=None):
    s = _s(s)
    return s[int(start):] if n is None else s[int(start):int(start) + int(n)]


def _extract(pattern, group, s):
    m = _safe_regex(pattern).search(_s(s))
    g = int(group)
    return m.group(g) if m and g <= m.re.groups else None


FUNCS = {
    "ago": lambda c, td: c.now - td, "now": lambda c: c.now,
    "tolower": lambda c, s: None if s is None else str(s).lower(), "toupper": lambda c, s: None if s is None else str(s).upper(),
    "strlen": lambda c, s: len(_s(s)), "substring": lambda c, *a: _substr(*a), "strcat": lambda c, *a: "".join(_s(x) for x in a),
    "toint": lambda c, x: int(float(x)) if x not in (None, "") else None, "tolong": lambda c, x: int(float(x)) if x not in (None, "") else None,
    "todouble": lambda c, x: float(x) if x not in (None, "") else None, "tostring": lambda c, x: None if x is None else str(x),
    "hourofday": lambda c, d: d.hour if isinstance(d, datetime) else None,
    "dayofweek": lambda c, d: (d.weekday() + 1) % 7 if isinstance(d, datetime) else None,   # Sunday = 0 like Kusto
    "startofday": lambda c, d: d.replace(hour=0, minute=0, second=0, microsecond=0) if isinstance(d, datetime) else None,
    "bin": lambda c, x, s: _bin(x, s), "floor": lambda c, x, s: _bin(x, s),
    "iff": lambda c, cond, a, b: a if cond else b, "coalesce": lambda c, *a: next((x for x in a if x not in (None, "")), None),
    "isnull": lambda c, x: x is None, "isnotnull": lambda c, x: x is not None,
    "isempty": lambda c, x: x in (None, ""), "isnotempty": lambda c, x: x not in (None, ""),
    "round": lambda c, x, n=0: None if x is None else round(x, int(n)), "abs": lambda c, x: None if x is None else abs(x),
    "split": lambda c, s, d: _s(s).split(_s(d)), "array_length": lambda c, a: len(a) if a is not None else None,
    "extract": lambda c, p, g, s: _extract(p, g, s), "ipv4_is_private": lambda c, ip: _is_private(ip),
    "_getwatchlist": lambda c, n: _watch(c, n), "watchlist": lambda c, n: _watch(c, n),
    "ti_match": lambda c, ip: (c.ti_lookup(str(ip)) if c.ti_lookup and ip else None),
}


def truthy(v) -> bool:
    return bool(v) if v is not None else False


def _cmp(op, a, b):
    try:
        if op == "==":
            return a == b
        if op == "!=":
            return a != b
        if op == "=~":
            return a is not None and _s(a).lower() == _s(b).lower()
        if op == "!~":
            return not (a is not None and _s(a).lower() == _s(b).lower())
        if op in ("<", "<=", ">", ">="):
            if a is None or b is None:
                return False
            return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
        if a is None:
            return False
        if op in ("contains", "has"):
            return _s(b).lower() in _s(a).lower()
        if op == "contains_cs":
            return _s(b) in _s(a)
        if op == "startswith":
            return _s(a).lower().startswith(_s(b).lower())
        if op == "endswith":
            return _s(a).lower().endswith(_s(b).lower())
        if op == "matches":
            return bool(_safe_regex(b).search(_s(a)[:2000]))
    except TypeError:
        return False
    raise KqlError(f"unsupported operator {op}")


def evaluate(node, row, ctx):
    k = node[0]
    if k == "lit":
        return node[1]
    if k == "id":
        return get_path(row, node[1])
    if k == "and":
        return truthy(evaluate(node[1], row, ctx)) and truthy(evaluate(node[2], row, ctx))
    if k == "or":
        return truthy(evaluate(node[1], row, ctx)) or truthy(evaluate(node[2], row, ctx))
    if k == "not":
        return not truthy(evaluate(node[1], row, ctx))
    if k == "neg":
        v = evaluate(node[1], row, ctx)
        return -v if isinstance(v, (int, float, timedelta)) else None
    if k == "cmp":
        return _cmp(node[1], evaluate(node[2], row, ctx), evaluate(node[3], row, ctx))
    if k == "in":
        a = evaluate(node[1], row, ctx)
        vals = []
        for item in node[2]:
            v = evaluate(item, row, ctx)
            vals.extend(v if isinstance(v, list) else [v])
        hit = a is not None and (a in vals or _s(a).lower() in {_s(v).lower() for v in vals})
        return not hit if node[3] else hit
    if k == "arith":
        a, b = evaluate(node[2], row, ctx), evaluate(node[3], row, ctx)
        try:
            return {"+": lambda: a + b, "-": lambda: a - b, "*": lambda: a * b, "/": lambda: a / b, "%": lambda: a % b}[node[1]]()
        except (TypeError, ZeroDivisionError):
            return None
    if k == "call":
        fn = FUNCS.get(node[1])
        if fn is None:
            raise KqlError(f"unknown function '{node[1]}'")
        try:
            return fn(ctx, *[evaluate(a, row, ctx) for a in node[2]])
        except (TypeError, ValueError, AttributeError):
            return None
    raise KqlError("cannot evaluate expression")


def _hashable(v):
    return tuple(_hashable(x) for x in v) if isinstance(v, (list, set)) else v


def _col_name(name, node, n):
    if name:
        return name
    if node[0] == "id":
        return node[1]
    if node[0] == "call" and node[1] in ("bin", "floor", "startofday") and node[2] and node[2][0][0] == "id":
        return node[2][0][1]
    return f"Column{n}"


def _agg(func, args, rows, ctx):
    if func == "count":
        return len(rows)
    vals = lambda: [evaluate(args[0], r, ctx) for r in rows]
    if func == "countif":
        return sum(1 for r in rows if truthy(evaluate(args[0], r, ctx)))
    if func == "dcount":
        return len({_hashable(v) for v in vals() if v is not None})
    nums = [v for v in vals() if isinstance(v, (int, float))]
    if func == "sum":
        return sum(nums)
    if func == "avg":
        return round(sum(nums) / len(nums), 3) if nums else None
    if func in ("min", "max"):
        vs = [v for v in vals() if v is not None]
        try:
            return (min if func == "min" else max)(vs) if vs else None
        except TypeError:
            return None
    limit = int(evaluate(args[1], {}, ctx)) if len(args) > 1 else 100
    if func == "make_set":
        return list(dict.fromkeys(_hashable(v) for v in vals() if v is not None))[:limit]
    if func == "make_list":
        return [v for v in vals() if v is not None][:limit]
    if func == "take_any":
        return next((v for v in vals() if v is not None), None)
    raise KqlError(f"unknown aggregate {func}")


def _sort_key(v):
    return ("num" if isinstance(v, (int, float)) else type(v).__name__, v)


def _sort(rows, keys, ctx):
    """Stable multi-key sort; NULL values always go last."""
    for expr, desc in reversed(keys):
        pairs = [(evaluate(expr, r, ctx), r) for r in rows]
        real, nulls = [p for p in pairs if p[0] is not None], [p for p in pairs if p[0] is None]
        try:
            real.sort(key=lambda p: _sort_key(p[0]), reverse=desc)
        except TypeError:
            real.sort(key=lambda p: _s(p[0]), reverse=desc)
        rows = [r for _, r in real + nulls]
    return rows


def run_stage(st, rows, ctx):
    kind = st[0]
    if kind == "where":
        return [r for r in rows if truthy(evaluate(st[1], r, ctx))]
    if kind == "take":
        return rows[:st[1]]
    if kind == "count":
        return [{"Count": len(rows)}]
    if kind == "project":
        return [{_col_name(n, e, i + 1): evaluate(e, r, ctx) for i, (n, e) in enumerate(st[1])} for r in rows]
    if kind == "project_away":
        return [{k: v for k, v in r.items() if k not in st[1]} for r in rows]
    if kind == "extend":
        out = []
        for r in rows:
            r2 = dict(r)
            for n, e in st[1]:
                r2[n] = evaluate(e, r2, ctx)
            out.append(r2)
        return out
    if kind == "distinct":
        seen, out = set(), []
        for r in rows:
            row = {_col_name(n, e, i + 1): evaluate(e, r, ctx) for i, (n, e) in enumerate(st[1])}
            key = tuple(_hashable(v) for v in row.values())
            if key not in seen:
                seen.add(key)
                out.append(row)
        return out
    if kind == "sort":
        return _sort(rows, st[1], ctx)
    if kind == "top":
        return _sort(rows, st[2], ctx)[:st[1]]
    if kind == "summarize":
        aggs, keys = st[1], st[2]
        groups: dict = {}
        for r in rows:
            kv = tuple(_hashable(evaluate(e, r, ctx)) for _, e in keys)
            groups.setdefault(kv, []).append(r)
        if not keys and not groups:
            groups[()] = []
        out = []
        for kv, grp in groups.items():
            row = {_col_name(n, e, i + 1): kv[i] for i, (n, e) in enumerate(keys)}
            for n, call in aggs:
                fn, args = call[1], call[2]
                default = f"{fn}_" + (args[0][1].replace(".", "_") if args and args[0][0] == "id" else "")
                row[n or default] = _agg(fn, args, grp, ctx)
            out.append(row)
        return out
    if kind == "render":
        return rows
    raise KqlError(f"unsupported stage {kind}")


@dataclass
class Result:
    columns: list
    rows: list
    scanned: int
    truncated: bool
    render: str | None = None


def run_query(text: str, tables: dict, ctx: Ctx | None = None, max_rows: int = 1000) -> Result:
    """tables: {name: callable returning list[dict]}. Raises KqlError with a helpful message."""
    ctx = ctx or Ctx()
    table, stages = parse(text)
    loader = tables.get(table)
    if loader is None:
        raise KqlError(f"unknown table '{table}'. Available: {', '.join(sorted(tables))}")
    rows = loader()
    scanned, render = len(rows), None
    for st in stages:
        if st[0] == "render":
            render = st[1]
        rows = run_stage(st, rows, ctx)
    cols: list = []
    for r in rows[:50]:
        for k in r:
            if k not in cols:
                cols.append(k)
    return Result(cols, rows[:max_rows], scanned, len(rows) > max_rows, render)


def to_jsonable(v):
    if isinstance(v, datetime):
        return v.isoformat()
    if isinstance(v, timedelta):
        return v.total_seconds()
    if isinstance(v, (list, tuple, set)):
        return [to_jsonable(x) for x in v]
    if isinstance(v, dict):
        return {k: to_jsonable(x) for k, x in v.items()}
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    return str(v)
