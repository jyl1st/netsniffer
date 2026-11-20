from dataclasses import dataclass

MAX_EXPRESSION = 8192
OPERATORS = ("&&", "||", "==", "!=", ">=", "<=", "!", ">", "<")
DELIMITERS = "(){},"
WORD_OPERATORS = {"and", "or", "not", "contains", "matches", "in"}
ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", '"': '"', "'": "'"}


class FilterError(ValueError):
    def __init__(self, message: str, position: int):
        super().__init__(message)
        self.position = position


@dataclass(frozen=True, slots=True)
class Token:
    kind: str
    text: str
    position: int


def tokenize(source: str) -> list[Token]:
    if len(source) > MAX_EXPRESSION:
        raise FilterError("显示过滤表达式过长", MAX_EXPRESSION)
    result = []
    cursor = 0
    while cursor < len(source):
        mark = source[cursor]
        if mark.isspace():
            cursor += 1
            continue
        if mark in "\"'":
            value, end = _string(source, cursor)
            result.append(Token("string", value, cursor))
            cursor = end
            continue
        if mark in DELIMITERS:
            result.append(Token(mark, mark, cursor))
            cursor += 1
            continue
        if mark in "!&|<>=":
            operator = next((candidate for candidate in OPERATORS if source.startswith(candidate, cursor)), None)
            if operator is None:
                raise FilterError(f"不完整的运算符 {mark}", cursor)
            result.append(Token("operator", operator, cursor))
            cursor += len(operator)
            continue
        start = cursor
        while cursor < len(source) and not source[cursor].isspace() and source[cursor] not in DELIMITERS + "!&|<>=\"'":
            cursor += 1
        word = source[start:cursor]
        keyword = word.casefold()
        result.append(Token("operator", keyword, start) if keyword in WORD_OPERATORS else Token("word", word, start))
    result.append(Token("end", "", len(source)))
    return result


def _string(source: str, start: int) -> tuple[str, int]:
    quotes = source[start]
    cursor = start + 1
    parts = []
    while cursor < len(source):
        character = source[cursor]
        cursor += 1
        if character == quotes:
            return "".join(parts), cursor
        if character != "\\" or cursor == len(source):
            parts.append(character)
            continue
        escape = source[cursor]
        cursor += 1
        if escape == "u" and cursor + 4 <= len(source):
            digits = source[cursor:cursor + 4]
            if all(digit in "0123456789abcdefABCDEF" for digit in digits):
                parts.append(chr(int(digits, 16)))
                cursor += 4
                continue
        # 保留正则转义，例如 \d 和 \x20。
        parts.append(ESCAPES.get(escape, "\\" + escape))
    raise FilterError("字符串缺少结束引号", start)
