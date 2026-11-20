import re
from decimal import Decimal
from ipaddress import ip_address, ip_network

from PySide6.QtCore import QRegularExpression

from sniffer.filter.ast import Compare, Exists, Expression, Logical, Not, Value
from sniffer.filter.fields import known_field
from sniffer.filter.lexer import FilterError, Token, tokenize

OPERATORS = {"==", "!=", ">", "<", ">=", "<=", "contains", "matches", "in"}
MAC_LITERAL = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}|(?:[0-9a-f]{2}-){5}[0-9a-f]{2}", re.I)
INTEGER = re.compile(r"[+-]?(?:[0-9]+|0[xX][0-9a-fA-F]+)")
DECIMAL = re.compile(r"[+-]?(?:[0-9]+\.[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?|[+-]?[0-9]+[eE][+-]?[0-9]+")
PCRE_LIMITS = "(*NO_JIT)(*LIMIT_MATCH=25000)(*LIMIT_DEPTH=128)"


def parse_filter(source: str) -> Expression:
    return _Parser(tokenize(source)).parse()


class _Parser:
    def __init__(self, tokens: list[Token]):
        self._tokens = tokens
        self._index = 0

    def parse(self) -> Expression:
        expression = self._or(0)
        token = self._peek()
        if token.kind != "end":
            raise FilterError(f"意外的内容 {token.text!r}，请检查运算符或括号", token.position)
        return expression

    def _peek(self) -> Token:
        return self._tokens[self._index]

    def _take(self) -> Token:
        token = self._peek()
        self._index += 1
        return token

    def _accept(self, kind: str, *text: str) -> bool:
        token = self._peek()
        if token.kind != kind or (text and token.text not in text):
            return False
        self._take()
        return True

    def _expect(self, kind: str, message: str) -> Token:
        if self._peek().kind != kind:
            raise FilterError(message, self._peek().position)
        return self._take()

    def _or(self, depth: int) -> Expression:
        terms = [self._and(depth)]
        while self._accept("operator", "||", "or"):
            terms.append(self._and(depth))
        return Logical("or", tuple(terms)) if len(terms) > 1 else terms[0]

    def _and(self, depth: int) -> Expression:
        terms = [self._unary(depth)]
        while self._accept("operator", "&&", "and"):
            terms.append(self._unary(depth))
        return Logical("and", tuple(terms)) if len(terms) > 1 else terms[0]

    def _unary(self, depth: int) -> Expression:
        if depth >= 64:
            raise FilterError("显示过滤分组过深", self._peek().position)
        if self._accept("operator", "!", "not"):
            return Not(self._unary(depth + 1))
        if self._accept("("):
            expression = self._or(depth + 1)
            self._expect(")", "缺少右括号 )")
            return expression
        return self._comparison()

    def _comparison(self) -> Expression:
        identifier = self._expect("word", "请输入协议或字段名")
        name = identifier.text.lower()
        if not known_field(name):
            raise FilterError(f"未知的协议或字段 {identifier.text}", identifier.position)
        operator = self._peek()
        if operator.kind != "operator" or operator.text not in OPERATORS:
            return Exists(name)
        self._take()
        if operator.text == "in":
            return Compare(name, "in", self._set())
        first = self._peek()
        value = self._value()
        if operator.text == "matches":
            if first.kind != "string":
                raise FilterError("matches 需要用引号括起的正则表达式", first.position)
            value = _regex(first)
        elif operator.text == "contains" and first.kind != "string":
            raise FilterError("contains 需要用引号括起的字符串", first.position)
        return Compare(name, operator.text, value)

    def _set(self) -> tuple[Value, ...]:
        self._expect("{", "in 需要一个以 { 开始的值集合")
        values = [self._value()]
        while self._accept(","):
            values.append(self._value())
        self._expect("}", "值集合需要逗号分隔，并以 } 结束")
        return tuple(values)

    def _value(self) -> Value:
        token = self._peek()
        if self._accept("string"):
            return token.text
        self._expect("word", "请输入数字、IP、网段、MAC 或带引号的字符串")
        text = token.text
        lower = text.lower()
        if lower in ("true", "false"):
            return lower == "true"
        if MAC_LITERAL.fullmatch(text):
            return lower.replace("-", ":")
        try:
            if INTEGER.fullmatch(text):
                return int(text, 16 if "0x" in lower else 10)
            if DECIMAL.fullmatch(text):
                return Decimal(text)
            if "/" in text:
                return ip_network(text, strict=False)
            return ip_address(text)
        except (ValueError, ArithmeticError):
            raise FilterError(f"无法识别的值 {text!r}，文本请加引号", token.position) from None


def _regex(token: Token) -> QRegularExpression:
    if len(token.text) > 512:
        raise FilterError("正则表达式过长", token.position)
    regex = QRegularExpression(PCRE_LIMITS + token.text, QRegularExpression.PatternOption.CaseInsensitiveOption)
    if not regex.isValid():
        offset = max(0, regex.patternErrorOffset() - len(PCRE_LIMITS))
        raise FilterError(f"正则表达式无效：{regex.errorString()}", token.position + 1 + offset)
    return regex
