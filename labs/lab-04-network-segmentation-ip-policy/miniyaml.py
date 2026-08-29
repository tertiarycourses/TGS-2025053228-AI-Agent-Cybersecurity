"""Tiny YAML-subset loader — standard library only.

Handles the restricted YAML this course uses: comments (#), key: value mappings,
nested mappings by indentation, and block sequences where each item is either a
scalar ('- value') or a mapping introduced by a bare '-' on its own line followed
by indented 'key: value' lines. Scalars are parsed as bool / int / float / str.
This is intentionally small and deterministic; it is NOT a full YAML parser.
"""

def _scalar(v):
    v = v.strip()
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        return v[1:-1]
    low = v.lower()
    if low in ("true", "yes"): return True
    if low in ("false", "no"): return False
    if low in ("null", "~", ""): return None
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        pass
    return v


def _rows(text):
    out = []
    for raw in text.splitlines():
        # strip trailing comments that are not inside quotes (our files never quote #)
        if "#" in raw:
            raw = raw[:raw.index("#")]
        if not raw.strip():
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        out.append((indent, raw.strip()))
    return out


def _parse(rows, i, indent):
    """Return (value, next_index) for the block at column >= indent starting at row i."""
    if i >= len(rows):
        return None, i
    first_ind, first_txt = rows[i]
    if first_txt == "-" or first_txt.startswith("- "):
        # sequence of scalars / bare '-' maps
        seq = []
        while i < len(rows) and rows[i][0] == first_ind and (rows[i][1] == "-" or rows[i][1].startswith("- ")):
            ind, txt = rows[i]
            if txt == "-":
                i += 1
                val, i = _parse(rows, i, ind + 1)
                seq.append(val)
            else:
                seq.append(_scalar(txt[2:]))
                i += 1
        return seq, i
    # mapping
    mapping = {}
    while i < len(rows) and rows[i][0] == first_ind:
        ind, txt = rows[i]
        if txt.startswith("- "):
            break
        if ":" not in txt:
            i += 1
            continue
        key, _, val = txt.partition(":")
        key = key.strip(); val = val.strip()
        if val == "":
            i += 1
            if i < len(rows) and rows[i][0] > ind:
                child, i = _parse(rows, i, rows[i][0])
                mapping[key] = child
            else:
                mapping[key] = None
        else:
            mapping[key] = _scalar(val)
            i += 1
    return mapping, i


def loads(text):
    rows = _rows(text)
    if not rows:
        return {}
    val, _ = _parse(rows, 0, rows[0][0])
    return val


def load(path):
    with open(path, "r", encoding="utf-8") as f:
        return loads(f.read())
