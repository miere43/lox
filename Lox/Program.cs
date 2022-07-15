using System.Text;

class Program
{
    private static readonly Interpreter interpreter = new();

    private static bool hadError = false;
    private static bool hadRuntimeError = false;

    public static int Main(string[] args)
    {
        if (args.Length > 1)
        {
            Console.WriteLine("Usage: jlox [script]");
            return 64;
        }
        else if (args.Length == 1)
        {
            return RunFile(args[0]);
        }
        else
        {
            return RunPrompt();
        }
    }

    private static int RunFile(string path)
    {
        Run(File.ReadAllText(path));
        if (hadError)
        {
            return 65;
        }
        else if (hadRuntimeError)
        {
            return 70;
        }
        return 0;
    }

    private static int RunPrompt()
    {
        using var stream = Console.OpenStandardInput();
        using var reader = new StreamReader(stream, leaveOpen: true);

        while (true)
        {
            Console.Write("> ");
            var line = reader.ReadLine();
            if (line == null)
            {
                break;
            }
            Run(line);
            hadError = false;
        }

        return 0;
    }

    private static void Run(string source)
    {
        var scanner = new Scanner(source);
        var tokens = scanner.ScanTokens();
        var parser = new Parser(tokens);
        var expression = parser.Parse();

        if (hadError || expression == null)
        {
            return;
        }

        interpreter.Interpret(expression);
    }

    public static void Error(int line, string message)
    {
        Report(line, "", message);
    }

    public static void Error(Token token, string message)
    {
        if (token.Type == TokenType.Eof)
        {
            Report(token.Line, " at end", message);
        }
        else
        {
            Report(token.Line, $"at '{token.Lexeme}'", message);
        }
    }

    public static void RuntimeError(RuntimeException exception)
    {
        Console.WriteLine($"{exception.Message}\n[line {exception.Token.Line}]");
        hadRuntimeError = true;
    }

    public static void Report(int line, string where, string message)
    {
        Console.WriteLine($"[line {line}] Error {where}: {message}");
        hadError = true;
    }
}

enum TokenType
{
    // Single-character tokens.
    LeftParen, RightParen, LeftBrace, RightBrace,
    Comma, Dot, Minus, Plus, Semicolon, Slash, Star,

    // One or two character tokens.
    Bang, BangEqual,
    Equal, EqualEqual,
    Greater, GreaterEqual,
    Less, LessEqual,

    // Literals.
    Identifier, String, Number,

    // Keywords.
    And, Class, Else, False, Fun, For, If, Nil, Or, Print, Return, Super, This, True, Var, While,

    Eof,
}

class Token
{
    public readonly TokenType Type;
    public readonly string Lexeme;
    public readonly object? Literal;
    public readonly int Line;

    public Token(TokenType type, string lexeme, object? literal, int line)
    {
        Type = type;
        Lexeme = lexeme;
        Literal = literal;
        Line = line;
    }

    public override string ToString()
    {
        return $"{Type} {Lexeme} {Literal}";
    }
}

class Scanner
{
    private static readonly Dictionary<string, TokenType> Keywords = new()
    {
        { "and", TokenType.And },
        { "class", TokenType.Class },
        { "else", TokenType.Else },
        { "false", TokenType.False },
        { "for", TokenType.For },
        { "fun", TokenType.Fun },
        { "if", TokenType.If },
        { "nil", TokenType.Nil },
        { "or", TokenType.Or },
        { "print", TokenType.Print },
        { "return", TokenType.Return },
        { "super", TokenType.Super },
        { "this", TokenType.This },
        { "true", TokenType.True },
        { "var", TokenType.Var },
        { "while", TokenType.While },
    };

    private readonly string source;
    private readonly List<Token> tokens = new();

    private int start = 0;
    private int current = 0;
    private int line = 1;

    private bool IsAtEnd => current >= source.Length;

    public Scanner(string source)
    {
        this.source = source;
    }

    public List<Token> ScanTokens()
    {
        while (!IsAtEnd)
        {
            start = current;
            ScanToken();
        }

        tokens.Add(new Token(TokenType.Eof, "", null, line));
        return tokens;
    }

    private void ScanToken()
    {
        var c = Advance();
        switch (c)
        {
            case '(': AddToken(TokenType.LeftParen); break;
            case ')': AddToken(TokenType.RightParen); break;
            case '{': AddToken(TokenType.LeftBrace); break;
            case '}': AddToken(TokenType.RightBrace); break;
            case ',': AddToken(TokenType.Comma); break;
            case '.': AddToken(TokenType.Dot); break;
            case '-': AddToken(TokenType.Minus); break;
            case '+': AddToken(TokenType.Plus); break;
            case ';': AddToken(TokenType.Semicolon); break;
            case '*': AddToken(TokenType.Star); break;

            case '!':
                AddToken(Match('=') ? TokenType.BangEqual : TokenType.Bang);
                break;

            case '=':
                AddToken(Match('=') ? TokenType.EqualEqual : TokenType.Equal);
                break;

            case '<':
                AddToken(Match('<') ? TokenType.LessEqual : TokenType.Less);
                break;

            case '>':
                AddToken(Match('>') ? TokenType.GreaterEqual : TokenType.Greater);
                break;

            case '/':
                if (Match('/'))
                {
                    // A comment goes until the end of the line.
                    while (Peek() != '\n' && !IsAtEnd)
                    {
                        Advance();
                    }
                }
                else
                {
                    AddToken(TokenType.Slash);
                }
                break;

            case ' ':
            case '\r':
            case '\t':
                break;

            case '\n':
                ++line;
                break;

            case '"':
                String();
                break;

            default:
                if (IsDigit(c))
                {
                    Number();
                }
                else if (IsAlpha(c))
                {
                    Identifier();
                }
                else
                {
                    Program.Error(line, "Unexpected character.");
                }
                break;
        }
    }

    private char Advance()
    {
        return source[current++];
    }

    private void AddToken(TokenType type)
    {
        AddToken(type, null);
    }

    private void AddToken(TokenType type, object? literal)
    {
        var text = source[start..current];
        tokens.Add(new Token(type, text, literal, line));
    }

    private bool Match(char expected)
    {
        if (IsAtEnd || source[current] != expected)
        {
            return false;
        }

        ++current;
        return true;
    }

    private char Peek()
    {
        return IsAtEnd ? '\0' : source[current];
    }

    private char PeekNext()
    {
        return current + 1 >= source.Length ? '\0' : source[current + 1];
    }

    private void String()
    {
        while (Peek() != '"' && !IsAtEnd)
        {
            if (Peek() == '\n')
            {
                ++line;
            }
            Advance();
        }

        if (IsAtEnd)
        {
            Program.Error(line, "Unterminated string.");
            return;
        }

        // The closing ".
        Advance();

        // Trim the surrounding quotes.
        var value = source.Substring(start + 1, (current - start) - 2);
        AddToken(TokenType.String, value);
    }

    private void Number()
    {
        while (IsDigit(Peek()))
        {
            Advance();
        }

        if (Peek() == '.' && IsDigit(PeekNext()))
        {
            Advance();
            while (IsDigit(Peek()))
            {
                Advance();
            }
        }

        AddToken(TokenType.Number, double.Parse(source[start..current]));
    }

    private void Identifier()
    {
        while (IsAlphaNumeric(Peek()))
        {
            Advance();
        }

        var text = source[start..current];
        var type = Keywords.GetValueOrDefault(text, TokenType.Identifier);
        AddToken(type);
    }

    private static bool IsDigit(char c)
    {
        return c >= '0' && c <= '9';
    }

    private static bool IsAlpha(char c)
    {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
    }

    private static bool IsAlphaNumeric(char c)
    {
        return IsDigit(c) || IsAlpha(c);
    }
}

abstract class Expression
{
    public abstract object? Evaluate(Interpreter intepreter);
}

abstract class Statement
{
    public abstract void Execute(Interpreter interpreter);
}

class BlockStatement : Statement
{
    public readonly List<Statement> Statements;

    public BlockStatement(List<Statement> statements)
    {
        Statements = statements;
    }

    public override void Execute(Interpreter interpreter)
    {
        var previous = interpreter.Environment;
        var environment = new Environment(previous);
        try
        {
            interpreter.Environment = environment;

            foreach (var statement in Statements)
            {
                statement.Execute(interpreter);
            }
        }
        finally
        {
            interpreter.Environment = previous;
        }
    }
}

class PrintStatement : Statement
{
    public readonly Expression Expression;

    public PrintStatement(Expression expression)
    {
        Expression = expression;
    }

    public override void Execute(Interpreter intepreter)
    {
        var value = Expression.Evaluate(intepreter);
        Console.WriteLine(Interpreter.Stringify(value));
    }
}

class ExpressionStatement : Statement
{
    public readonly Expression Expression;

    public ExpressionStatement(Expression expression)
    {
        Expression = expression;
    }

    public override void Execute(Interpreter interpreter)
    {
        Expression.Evaluate(interpreter);
    }
}

class VariableDeclaration : Statement
{
    public readonly Token Name;
    public readonly Expression? Initializer;

    public VariableDeclaration(Token name, Expression? initializer)
    {
        Name = name;
        Initializer = initializer;
    }

    public override void Execute(Interpreter interpreter)
    {
        var value = Initializer?.Evaluate(interpreter);
        interpreter.Environment.Define(Name.Lexeme, value);
    }
}

class BinaryExpression : Expression
{
    public readonly Expression Left;
    public readonly Token Operator;
    public readonly Expression Right;

    public BinaryExpression(Expression left, Token @operator, Expression right)
    {
        Left = left;
        Operator = @operator;
        Right = right;
    }

    public override object? Evaluate(Interpreter interpreter)
    {
        var rawLeft = Left.Evaluate(interpreter);
        var rawRight = Right.Evaluate(interpreter);

        switch (Operator.Type)
        {
            case TokenType.Greater:
            {
                var (left, right) = ExpectNumbers(Operator, rawLeft, rawRight);
                return left > right;
            }

            case TokenType.GreaterEqual:
            {
                var (left, right) = ExpectNumbers(Operator, rawLeft, rawRight);
                return left >= right;
            }

            case TokenType.Less:
            {
                var (left, right) = ExpectNumbers(Operator, rawLeft, rawRight);
                return left < right;
            }

            case TokenType.LessEqual:
            {
                var (left, right) = ExpectNumbers(Operator, rawLeft, rawRight);
                return left <= right;
            }

            case TokenType.Minus:
            {
                var (left, right) = ExpectNumbers(Operator, rawLeft, rawRight);
                return left - right;
            }

            case TokenType.Plus:
                if (rawLeft is double numberLeft && rawRight is double numberRight)
                {
                    return numberLeft + numberRight;
                }
                else if (rawLeft is string stringLeft && rawRight is string stringRight)
                {
                    return stringLeft + stringRight;
                }
                throw new RuntimeException(Operator, "Operands must be two numbers or two strings.");

            case TokenType.Slash:
            {
                var (left, right) = ExpectNumbers(Operator, rawLeft, rawRight);
                return left / right;
            }
            
            case TokenType.Star:
            {
                var (left, right) = ExpectNumbers(Operator, rawLeft, rawRight);
                return left * right;
            }
            
            case TokenType.BangEqual:
                return !IsEqual(rawLeft, rawRight);

            case TokenType:
                return IsEqual(rawLeft, rawRight);
            
            default:
                throw new NotImplementedException();
        }
    }

    private static bool IsEqual(object? left, object? right)
    {
        if (left == null && right == null)
        {
            return true;
        }
        else if (left == null)
        {
            return false;
        }
        return left.Equals(right);
    }

    private static (double Left, double Right) ExpectNumbers(Token op, object? left, object? right)
    {
        if (left is double numberLeft && right is double numberRight)
        {
            return (numberLeft, numberRight);
        }
        throw new RuntimeException(op, $"Operands must be numbers.");
    }
}

class UnaryExpression : Expression
{
    public readonly Token Operator;
    public readonly Expression Right;

    public UnaryExpression(Token @operator, Expression right)
    {
        Operator = @operator;
        Right = right;
    }

    public override object? Evaluate(Interpreter interpreter)
    {
        var right = Right.Evaluate(interpreter);

        switch (Operator.Type)
        {
            case TokenType.Bang:
                if (right == null)
                {
                    return false;
                }
                else if (right is bool boolean)
                {
                    return boolean;
                }
                return false;

            case TokenType.Minus:
                if (right is double number)
                {
                    return -number;
                }
                throw new RuntimeException(Operator, $"Operand must be a number.");
            
            default:
                throw new NotImplementedException();
        }
    }
}

class LiteralExpression : Expression
{
    public readonly object? Value;

    public LiteralExpression(object? value)
    {
        Value = value;
    }

    public override object? Evaluate(Interpreter interpreter)
    {
        return Value;
    }
}

class GroupingExpression : Expression
{
    public readonly Expression Expression;

    public GroupingExpression(Expression expression)
    {
        Expression = expression;
    }

    public override object? Evaluate(Interpreter interpreter)
    {
        return Expression.Evaluate(interpreter);
    }
}

class VariableExpression : Expression
{
    public readonly Token Name;

    public VariableExpression(Token name)
    {
        Name = name;
    }

    public override object? Evaluate(Interpreter interpreter)
    {
        return interpreter.Environment.Get(Name);
    }
}

class AssignmentExpression : Expression
{
    public readonly Token Token;
    public readonly Expression Value;

    public AssignmentExpression(Token token, Expression value)
    {
        Token = token;
        Value = value;
    }

    public override object? Evaluate(Interpreter interpreter)
    {
        var value = Value.Evaluate(interpreter);
        interpreter.Environment.Assign(Token, value);
        return value;
    }
}

class Environment
{
    private readonly Dictionary<string, object?> values = new();

    public readonly Environment? Enclosing;

    public Environment(Environment? enclosing = null)
    {
        Enclosing = enclosing;
    }

    public void Define(string name, object? value)
    {
        values[name] = value;
    }

    public object? Get(Token name)
    {
        if (values.TryGetValue(name.Lexeme, out var value))
        {
            return value;
        }
        else if (Enclosing != null)
        {
            return Enclosing.Get(name);
        }

        throw new RuntimeException(name, $"Undefined variable '{name.Lexeme}'.");
    }

    public void Assign(Token token, object? value)
    {
        if (!values.ContainsKey(token.Lexeme))
        {
            throw new RuntimeException(token, $"Undefined variable '{token.Lexeme}'.");
        }
        else if (Enclosing != null)
        {
            Enclosing.Assign(token, value);
        }
        else
        {
            values[token.Lexeme] = value;
        }
    }
}

class AstPrinter
{
    public void Print(Expression expression)
    {
        Console.WriteLine(ExpressionToString(expression));
    }

    private string Parenthesize(string name, params Expression[] expressions)
    {
        var builder = new StringBuilder();

        builder.Append('(').Append(name);
        foreach (var expression in expressions)
        {
            builder.Append(' ');
            builder.Append(ExpressionToString(expression));
        }
        builder.Append(')');

        return builder.ToString();
    }

    private string ExpressionToString(Expression expression)
    {
        return expression switch
        {
            LiteralExpression literal => literal.Value?.ToString() ?? "nil",
            BinaryExpression binary => Parenthesize(binary.Operator.Lexeme, binary.Left, binary.Right),
            UnaryExpression unary => Parenthesize(unary.Operator.Lexeme, unary.Right),
            GroupingExpression grouping => Parenthesize("group", grouping.Expression),
            _ => throw new NotImplementedException(),
        };
    }
}

class Parser
{
    private readonly List<Token> tokens;
    private int current = 0;

    public Parser(List<Token> tokens)
    {
        this.tokens = tokens;
    }

    public List<Statement> Parse()
    {
        try
        {
            var statements = new List<Statement>();
            while (!IsAtEnd)
            {
                var declaration = Declaration();
                if (declaration != null)
                {
                    statements.Add(declaration);
                }
            }
            return statements;
        }
        catch (ParseException)
        {
            return new List<Statement>();
        }
    }

    private Statement? Declaration()
    {
        try
        {
            if (Match(TokenType.Var))
            {
                return VariableDeclaration();
            }
            return Statement();
        }
        catch (ParseException)
        {
            Synchronize();
            return null;
        }
    }

    private Statement VariableDeclaration()
    {
        var name = Consume(TokenType.Identifier, "Expect variable name.");

        Expression? initializer = null;
        if (Match(TokenType.Equal))
        {
            initializer = Expression();
        }

        Consume(TokenType.Semicolon, "Expect ';' after variable declaration.");
        return new VariableDeclaration(name, initializer);
    }

    private Statement Statement()
    {
        if (Match(TokenType.Print))
        {
            return PrintStatement();
        }
        else if (Match(TokenType.LeftBrace))
        {
            return new BlockStatement(BlockStatement());
        }
        return ExpressionStatement();
    }

    private Statement ExpressionStatement()
    {
        var value = Assignment();
        Consume(TokenType.Semicolon, "Expect ';' after value.");
        return new ExpressionStatement(value);
    }

    private Statement PrintStatement()
    {
        var value = Expression();
        Consume(TokenType.Semicolon, "Expect ';' after value.");
        return new PrintStatement(value);
    }

    private List<Statement> BlockStatement()
    {
        var statements = new List<Statement>();

        while (!Check(TokenType.RightBrace) && !IsAtEnd)
        {
            var declaration = Declaration();
            if (declaration != null)
            {
                statements.Add(declaration);
            }
        }

        Consume(TokenType.RightBrace, "Expect '}' after block.");
        return statements;
    }

    private Expression Expression()
    {
        return Equality();
    }

    private Expression Assignment()
    {
        var expression = Equality();

        if (Match(TokenType.Equal))
        {
            var equals = Previous();
            var value = Assignment();

            if (expression is VariableExpression variableExpression)
            {
                var name = variableExpression.Name;
                return new AssignmentExpression(name, value);
            }

            Error(equals, "Invalid assignment target.");
        }

        return expression;
    }

    private Expression Equality()
    {
        var expression = Comparison();

        while (Match(TokenType.BangEqual, TokenType.EqualEqual))
        {
            var op = Previous();
            var right = Comparison();
            expression = new BinaryExpression(expression, op, right);
        }

        return expression;
    }

    private Expression Comparison()
    {
        var expression = Term();
    
        if (Match(TokenType.Greater, TokenType.GreaterEqual, TokenType.Less, TokenType.LessEqual))
        {
            var op = Previous();
            var right = Term();
            expression = new BinaryExpression(expression, op, right);
        }

        return expression;
    }

    private Expression Term()
    {
        var expression = Factor();

        while (Match(TokenType.Minus, TokenType.Plus))
        {
            var op = Previous();
            var right = Factor();
            expression = new BinaryExpression(expression, op, right);
        }

        return expression;
    }

    private Expression Factor()
    {
        var expression = Unary();

        while (Match(TokenType.Slash, TokenType.Star))
        {
            var op = Previous();
            var right = Unary();
            expression = new BinaryExpression(expression, op, right);
        }

        return expression;
    }

    private Expression Unary()
    {
        if (Match(TokenType.Bang, TokenType.Minus))
        {
            var op = Previous();
            var right = Unary();
            return new UnaryExpression(op, right);
        }

        return Primary();
    }

    private Expression Primary()
    {
        if (Match(TokenType.False))
        {
            return new LiteralExpression(false);
        }
        else if (Match(TokenType.True))
        {
            return new LiteralExpression(true);
        }
        else if (Match(TokenType.Nil))
        {
            return new LiteralExpression(null);
        }
        else if (Match(TokenType.Number, TokenType.String))
        {
            return new LiteralExpression(Previous().Literal);
        }
        else if (Match(TokenType.Identifier))
        {
            return new VariableExpression(Previous());
        }
        else if (Match(TokenType.LeftParen))
        {
            var expression = Expression();
            Consume(TokenType.RightParen, "Expected ')' after expression.");
            return new GroupingExpression(expression);
        }

        throw Error(Peek(), "Expect expression.");
    }

    private bool Match(params TokenType[] types)
    {
        foreach (var type in types)
        {
            if (Check(type))
            {
                Advance();
                return true;
            }
        }
        
        return false;
    }

    private Token Consume(TokenType type, string message)
    {
        if (Check(type))
        {
            return Advance();
        }

        throw Error(Peek(), message);
    }

    private static ParseException Error(Token token, string message)
    {
        Program.Error(token, message);
        return new ParseException();
    }

    private void Synchronize()
    {
        Advance();

        while (!IsAtEnd)
        {
            if (Previous().Type == TokenType.Semicolon)
            {
                break;
            }

            switch (Peek().Type)
            {
                case TokenType.Class:
                case TokenType.Fun:
                case TokenType.Var:
                case TokenType.For:
                case TokenType.If:
                case TokenType.While:
                case TokenType.Print:
                case TokenType.Return:
                    break;
            }

            Advance();
        }
    }

    private bool Check(TokenType type)
    {
        if (IsAtEnd)
        {
            return false;
        }
        return Peek().Type == type;
    }

    private Token Peek()
    {
        return tokens[current];
    }

    private Token Advance()
    {
        if (!IsAtEnd)
        {
            ++current;
        }
        return Previous();
    }

    private Token Previous()
    {
        return tokens[current - 1];
    }

    private bool IsAtEnd => Peek().Type == TokenType.Eof;
}

class ParseException : Exception
{
}

class RuntimeException : Exception
{
    public readonly Token Token;

    public RuntimeException(Token token, string? message) : base(message)
    {
        Token = token;
    }
}

class Interpreter
{
    public Environment Environment = new();

    public void Interpret(List<Statement> statements)
    {
        try
        {
            foreach (var statement in statements)
            {
                statement.Execute(this);
            }
        }
        catch (RuntimeException exception)
        {
            Program.RuntimeError(exception);
        }
    }

    public static string Stringify(object? value)
    {
        return value?.ToString() ?? "nil";
    }
}