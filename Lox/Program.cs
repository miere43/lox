using System.Diagnostics.CodeAnalysis;
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
        var statements = parser.Parse();

        if (hadError || statements == null)
        {
            return;
        }

        var resolver = new Resolver(interpreter);
        resolver.Resolve(statements);

        if (hadError)
        {
            return;
        }

        interpreter.Interpret(statements);
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
                AddToken(Match('=') ? TokenType.LessEqual : TokenType.Less);
                break;

            case '>':
                AddToken(Match('=') ? TokenType.GreaterEqual : TokenType.Greater);
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
    public abstract object? Evaluate(Interpreter interpreter);
    public abstract void Resolve(Resolver resolver);
}

abstract class Statement
{
    public abstract void Execute(Interpreter interpreter);
    public abstract void Resolve(Resolver resolver);
}

class WhileStatement : Statement
{
    public readonly Expression Condition;
    public readonly Statement Body;

    public WhileStatement(Expression condition, Statement body)
    {
        Condition = condition;
        Body = body;
    }

    public override void Execute(Interpreter interpreter)
    {
        while (Interpreter.IsTruthy(Condition.Evaluate(interpreter)))
        {
            Body.Execute(interpreter);
        }
    }

    public override void Resolve(Resolver resolver)
    {
        Condition.Resolve(resolver);
        Body.Resolve(resolver);
    }
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
        var environment = new Environment(interpreter.Environment);
        interpreter.ExecuteBlock(Statements, environment);
    }

    public override void Resolve(Resolver resolver)
    {
        resolver.BeginScope();
        resolver.Resolve(Statements);
        resolver.EndScope();
    }
}

class IfStatement : Statement
{
    public readonly Expression Condition;
    public readonly Statement ThenBranch;
    public readonly Statement? ElseBranch;

    public IfStatement(Expression condition, Statement thenBranch, Statement? elseBranch)
    {
        Condition = condition;
        ThenBranch = thenBranch;
        ElseBranch = elseBranch;
    }

    public override void Execute(Interpreter interpreter)
    {
        var value = Condition.Evaluate(interpreter);
        if (Interpreter.IsTruthy(value))
        {
            ThenBranch.Execute(interpreter);
        }
        else if (ElseBranch != null)
        {
            ElseBranch.Execute(interpreter);
        }
    }

    public override void Resolve(Resolver resolver)
    {
        Condition.Resolve(resolver);
        ThenBranch.Resolve(resolver);
        ElseBranch?.Resolve(resolver);
    }
}

class PrintStatement : Statement
{
    public readonly Expression Expression;

    public PrintStatement(Expression expression)
    {
        Expression = expression;
    }

    public override void Execute(Interpreter interpreter)
    {
        var value = Expression.Evaluate(interpreter);
        Console.WriteLine(Interpreter.Stringify(value));
    }

    public override void Resolve(Resolver resolver)
    {
        Expression.Resolve(resolver);
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

    public override void Resolve(Resolver resolver)
    {
        Expression.Resolve(resolver);
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

    public override void Resolve(Resolver resolver)
    {
        resolver.Declare(Name);
        Initializer?.Resolve(resolver);
        resolver.Define(Name);
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

    public override void Resolve(Resolver resolver)
    {
        Left.Resolve(resolver);
        Right.Resolve(resolver);
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

    public override void Resolve(Resolver resolver)
    {
        Right.Resolve(resolver);
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

    public override void Resolve(Resolver resolver)
    {
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

    public override void Resolve(Resolver resolver)
    {
        Expression.Resolve(resolver);
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
        return interpreter.LookupVariable(Name, this);
    }

    public override void Resolve(Resolver resolver)
    {
        if (resolver.Scopes.Count > 0 && resolver.Scopes[^1].TryGetValue(Name.Lexeme, out var value) && value == false)
        {
            Program.Error(Name, "Can't read local variable in its own initializer.");
        }

        resolver.ResolveLocal(this, Name);
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

        if (interpreter.Locals.TryGetValue(this, out var depth))
        {
            interpreter.Environment.AssignAt(depth, Token, value);
        }
        else
        {
            interpreter.Globals.Assign(Token, value);
        }

        return value;
    }

    public override void Resolve(Resolver resolver)
    {
        Value.Resolve(resolver);
        resolver.ResolveLocal(this, Token);
    }
}

class LogicalExpression : Expression
{
    public readonly Expression Left;
    public readonly Token Operator;
    public readonly Expression Right;

    public LogicalExpression(Expression left, Token op, Expression right)
    {
        Left = left;
        Operator = op;
        Right = right;
    }

    public override object? Evaluate(Interpreter interpreter)
    {
        var left = Left.Evaluate(interpreter);

        switch (Operator.Type)
        {
            case TokenType.Or:
                if (Interpreter.IsTruthy(left))
                {
                    return left;
                }
                break;

            case TokenType.And:
                if (!Interpreter.IsTruthy(left))
                {
                    return left;
                }
                break;
        }

        return Right.Evaluate(interpreter);
    }

    public override void Resolve(Resolver resolver)
    {
        Left.Resolve(resolver);
        Right.Resolve(resolver);
    }
}

class CallExpression : Expression
{
    public readonly Expression Callee;
    public readonly Token Paren;
    public readonly List<Expression> Arguments;

    public CallExpression(Expression callee, Token paren, List<Expression> arguments)
    {
        Callee = callee;
        Paren = paren;
        Arguments = arguments;
    }

    public override object? Evaluate(Interpreter interpreter)
    {
        var callee = Callee.Evaluate(interpreter);

        var arguments = new List<object?>();
        foreach (var argument in Arguments)
        {
            arguments.Add(argument.Evaluate(interpreter));
        }

        if (callee is Callable function)
        {
            if (function.Arity != arguments.Count)
            {
                throw new RuntimeException(Paren, $"Expected {function.Arity} arguments but got {arguments.Count}.");
            }

            return function.Call(interpreter, arguments);
        }
        else
        {
            throw new RuntimeException(Paren, "Can only call functions and classes.");
        }
    }

    public override void Resolve(Resolver resolver)
    {
        Callee.Resolve(resolver);

        foreach (var argument in Arguments)
        {
            argument.Resolve(resolver);
        }
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
            if (Enclosing != null)
            {
                Enclosing.Assign(token, value);
            }
            else
            {
               throw new RuntimeException(token, $"Undefined variable '{token.Lexeme}'.");
            }
        }
        else
        {
            values[token.Lexeme] = value;
        }
    }

    public object? GetAt(int depth, string name)
    {
        return Ancestor(depth).values[name];
    }

    private Environment Ancestor(int depth)
    {
        var environment = this;
        for (int i = 0; i < depth; ++i)
        {
            environment = environment.Enclosing;
            if (environment == null)
            {
                throw new InvalidOperationException();
            }
        }
        return environment;
    }

    public void AssignAt(int depth, Token token, object? value)
    {
        Ancestor(depth).values[token.Lexeme] = value;
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
            if (Match(TokenType.Class))
            {
                return ClassDeclaration();
            }
            else if (Match(TokenType.Fun))
            {
                return FunctionDeclaration("function");
            }
            else if (Match(TokenType.Var))
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

    private Statement ClassDeclaration()
    {
        var name = Consume(TokenType.Identifier, "Expect class name.");
        Consume(TokenType.LeftBrace, "Expect '{' before class body.");

        var methods = new List<FunctionDeclaration>();
        while (!Check(TokenType.RightBrace) && !IsAtEnd)
        {
            methods.Add(FunctionDeclaration("method"));
        }

        Consume(TokenType.RightBrace, "Expect '}' after class body.");

        return new ClassDeclaration(name, methods);
    }

    private FunctionDeclaration FunctionDeclaration(string kind)
    {
        var name = Consume(TokenType.Identifier, $"Expected {kind} name.");
        Consume(TokenType.LeftParen, $"Expect '(' after {kind} name.");

        var parameters = new List<Token>();
        if (!Check(TokenType.RightParen))
        {
            do
            {
                if (parameters.Count >= 255)
                {
                    Error(Peek(), "Can't have more than 255 parameters.");
                }

                parameters.Add(Consume(TokenType.Identifier, "Expect parameter name."));
            }
            while (Match(TokenType.Comma));
        }
        Consume(TokenType.RightParen, "Expect '(' after parameters.");

        Consume(TokenType.LeftBrace, $"Expect '{{' before {kind} body.");
        var body = BlockStatement();
        return new FunctionDeclaration(name, parameters, body);
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

    private Statement WhileStatement()
    {
        Consume(TokenType.LeftParen, "Expect '(' after 'while'.");
        var condition = Expression();
        Consume(TokenType.RightParen, "Expect ')' after condition.");
        var body = Statement();

        return new WhileStatement(condition, body);
    }

    private Statement ForStatement()
    {
        Consume(TokenType.LeftParen, "Expect '(' after 'for'.");

        Statement? initializer;
        if (Match(TokenType.Semicolon))
        {
            initializer = null;
        }
        else if (Match(TokenType.Var))
        {
            initializer = VariableDeclaration();
        }
        else
        {
            initializer = ExpressionStatement();
        }

        var condition = Check(TokenType.Semicolon) ? null : Expression();
        Consume(TokenType.Semicolon, "Expect ';' after loop condition.");

        var increment = Check(TokenType.RightParen) ? null : Expression();
        Consume(TokenType.RightParen, "Expect ')' after for clauses.");

        var body = Statement();

        if (increment != null)
        {
            body = new BlockStatement(new()
            {
                body,
                new ExpressionStatement(increment)
            });
        }

        if (condition == null)
        {
            condition = new LiteralExpression(true);
        }

        body = new WhileStatement(condition, body);

        if (initializer != null)
        {
            body = new BlockStatement(new()
            {
                initializer,
                body,
            });
        }

        return body;
    }

    private Statement Statement()
    {
        if (Match(TokenType.For))
        {
            return ForStatement();
        }
        else if (Match(TokenType.If))
        {
            return IfStatement();
        }
        else if (Match(TokenType.While))
        {
            return WhileStatement();
        }
        else if (Match(TokenType.Print))
        {
            return PrintStatement();
        }
        else if (Match(TokenType.Return))
        {
            return ReturnStatement();
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

    private Statement IfStatement()
    {
        Consume(TokenType.LeftParen, "Expect '(' after 'if'.");
        var condition = Expression();
        Consume(TokenType.RightParen, "Expect ')' after 'if'.");

        var thenBranch = Statement();
        var elseBranch = Match(TokenType.Else) ? Statement() : null;

        return new IfStatement(condition, thenBranch, elseBranch);
    }

    private Statement ReturnStatement()
    {
        var keyword = Previous();
        var value = Check(TokenType.Semicolon) ? null : Expression();
        Consume(TokenType.Semicolon, "Expect ';' after return value.");
        return new ReturnStatement(keyword, value);
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
        return Assignment();
    }

    private Expression And()
    {
        var expression = Equality();

        while (Match(TokenType.And))
        {
            var op = Previous();
            var right = Equality();
            expression = new LogicalExpression(expression, op, right);
        }

        return expression;
    }

    private Expression Or()
    {
        var expression = And();

        while (Match(TokenType.Or))
        {
            var op = Previous();
            var right = And();
            expression = new LogicalExpression(expression, op, right);
        }

        return expression;
    }

    private Expression Assignment()
    {
        var expression = Or();

        if (Match(TokenType.Equal))
        {
            var equals = Previous();
            var value = Assignment();

            if (expression is VariableExpression variableExpression)
            {
                var name = variableExpression.Name;
                return new AssignmentExpression(name, value);
            }
            else if (expression is GetExpression getExpression)
            {
                return new SetExpression(getExpression.Object, getExpression.Name, value);
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

        return Call();
    }

    private Expression Call()
    {
        var expression = Primary();

        while (true)
        {
            if (Match(TokenType.LeftParen))
            {
                expression = FinishCall(expression);
            }
            else if (Match(TokenType.Dot))
            {
                var name = Consume(TokenType.Identifier, "Expect property name after '.'.");
                expression = new GetExpression(expression, name);
            }
            else
            {
                break;
            }
        }

        return expression;
    }

    private Expression FinishCall(Expression callee)
    {
        var arguments = new List<Expression>();
        if (!Check(TokenType.RightParen))
        {
            do
            {
                if (arguments.Count >= 255)
                {
                    Error(Peek(), "Can't have more than 255 arguments.");
                }
                arguments.Add(Expression());
            }
            while (Match(TokenType.Comma));
        }

        var paren = Consume(TokenType.RightParen, "Expect ')' after arguments.");

        return new CallExpression(callee, paren, arguments);
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
        else if (Match(TokenType.This))
        {
            return new ThisExpression(Previous());
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

class ThisExpression : Expression
{
    public readonly Token Keyword;

    public ThisExpression(Token keyword)
    {
        Keyword = keyword;
    }

    public override void Resolve(Resolver resolver)
    {
        if (resolver.CurrentClass == ClassType.None)
        {
            Program.Error(Keyword, "Can't use 'this' outside of a class.");
            return;
        }

        resolver.ResolveLocal(this, Keyword);
    }

    public override object? Evaluate(Interpreter interpreter)
    {
        return interpreter.LookupVariable(Keyword, this);
    }
}

class SetExpression : Expression
{
    public readonly Expression Object;
    public readonly Token Name;
    public readonly Expression Value;

    public SetExpression(Expression obj, Token name, Expression value)
    {
        Object = obj;
        Name = name;
        Value = value;
    }

    public override object? Evaluate(Interpreter interpreter)
    {
        var obj = Object.Evaluate(interpreter);
        if (obj is not RuntimeClassInstance instance)
        {
            throw new RuntimeException(Name, "Only instances have fields.");
        }

        var value = Value.Evaluate(interpreter);
        instance.Set(Name, value);
        return value;
    }

    public override void Resolve(Resolver resolver)
    {
        Value.Resolve(resolver);
        Object.Resolve(resolver);
    }
}

class GetExpression : Expression
{
    public readonly Expression Object;
    public readonly Token Name;

    public GetExpression(Expression obj, Token name)
    {
        Object = obj;
        Name = name;
    }

    public override void Resolve(Resolver resolver)
    {
        Object.Resolve(resolver);
    }

    public override object? Evaluate(Interpreter interpreter)
    {
        var value = Object.Evaluate(interpreter);
        if (value is not RuntimeClassInstance instance)
        {
            throw new RuntimeException(Name, "Only instances have properties.");
        }
        return instance.Get(Name);
    }
}

class ClassDeclaration : Statement
{
    public readonly Token Name;
    public readonly List<FunctionDeclaration> Methods;

    public ClassDeclaration(Token name, List<FunctionDeclaration> methods)
    {
        Name = name;
        Methods = methods;
    }

    public override void Execute(Interpreter interpreter)
    {
        interpreter.Environment.Define(Name.Lexeme, null);

        var methods = new Dictionary<string, RuntimeFunction>();
        foreach (var method in Methods)
        {
            var function = new RuntimeFunction(method, interpreter.Environment, method.Name.Lexeme == "init");
            methods[method.Name.Lexeme] = function;
        }

        var cls = new RuntimeClass(Name.Lexeme, methods);
        interpreter.Environment.Assign(Name, cls);
    }

    public override void Resolve(Resolver resolver)
    {
        var enclosingClass = resolver.CurrentClass;
        resolver.CurrentClass = ClassType.Class;

        resolver.Declare(Name);
        resolver.Define(Name);

        resolver.BeginScope();
        resolver.Scopes[^1]["this"] = true;

        foreach (var method in Methods)
        {
            resolver.ResolveFunction(method, method.Name.Lexeme == "init" ? FunctionType.Initializer : FunctionType.Method);
        }

        resolver.EndScope();

        resolver.CurrentClass = enclosingClass;
    }
}

class RuntimeClass : Callable
{
    public readonly string Name;
    private readonly Dictionary<string, RuntimeFunction> methods;

    public override int Arity
    {
        get
        {
            var initializer = FindMethod("init");
            return initializer?.Arity ?? 0;
        }
    }

    public RuntimeClass(string name, Dictionary<string, RuntimeFunction> methods)
    {
        Name = name;
        this.methods = methods;
    }

    public override object? Call(Interpreter interpreter, List<object?> arguments)
    {
        var instance = new RuntimeClassInstance(this);
        var initializer = FindMethod("init");
        initializer?.Bind(instance).Call(interpreter, arguments);
        return instance;
    }

    public override string ToString()
    {
        return Name;
    }

    public RuntimeFunction? FindMethod(string name)
    {
        return methods.TryGetValue(name, out var method) ? method : null;
    }
}

class RuntimeClassInstance
{
    public readonly RuntimeClass Class;
    private readonly Dictionary<string, object?> fields = new();

    public RuntimeClassInstance(RuntimeClass cls)
    {
        Class = cls;
    }

    public override string ToString()
    {
        return $"{Class} instance";
    }

    public object? Get(Token name)
    {
        if (fields.TryGetValue(name.Lexeme, out var value))
        {
            return value;
        }

        var method = Class.FindMethod(name.Lexeme);
        if (method != null)
        {
            return method.Bind(this);
        }

        throw new RuntimeException(name, $"Undefined property '{name.Lexeme}'.");
    }

    public void Set(Token name, object? value)
    {
        fields[name.Lexeme] = value;
    }
}

class ReturnStatement : Statement
{
    public readonly Token Keyword;
    public readonly Expression? Value;

    public ReturnStatement(Token keyword, Expression? value)
    {
        Keyword = keyword;
        Value = value;
    }

    public override void Execute(Interpreter interpreter)
    {
        throw new ReturnException(Value?.Evaluate(interpreter));
    }

    public override void Resolve(Resolver resolver)
    {
        if (resolver.CurrentFunction == FunctionType.None)
        {
            Program.Error(Keyword, "Can't return from top-level code.");
        }

        if (Value != null)
        {
            if (resolver.CurrentFunction == FunctionType.Initializer)
            {
                Program.Error(Keyword, "Can't return a value from an initializer.");
            }

            Value.Resolve(resolver);
        }
    }
}

internal class ReturnException : Exception
{
    public readonly object? Value;

    public ReturnException(object? value)
    {
        Value = value;
    }
}

class FunctionDeclaration : Statement
{
    public readonly Token Name;
    public readonly List<Token> Parameters;
    public readonly List<Statement> Body;

    public FunctionDeclaration(Token name, List<Token> parameters, List<Statement> body)
    {
        Name = name;
        Parameters = parameters;
        Body = body;
    }

    public override void Execute(Interpreter interpreter)
    {
        var function = new RuntimeFunction(this, interpreter.Environment, false);
        interpreter.Environment.Define(Name.Lexeme, function);
    }

    public override void Resolve(Resolver resolver)
    {
        resolver.Declare(Name);
        resolver.Define(Name);
        resolver.ResolveFunction(this, FunctionType.Function);
    }
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
    public Environment Globals = new();
    public Environment Environment;
    public Dictionary<Expression, int> Locals = new();

    public Interpreter()
    {
        Environment = Globals;

        Globals.Define("clock", new FuncCallable((interpreter, arguments) =>
        {
            return new TimeSpan(DateTime.UtcNow.Ticks).TotalSeconds;
        }, 0));
    }

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

    public void ExecuteBlock(List<Statement> statements, Environment environment)
    {
        var previous = Environment;
        try
        {
            Environment = environment;

            foreach (var statement in statements)
            {
                statement.Execute(this);
            }
        }
        finally
        {
            Environment = previous;
        }
    }

    public void Resolve(Expression expression, int depth)
    {
        Locals[expression] = depth;
    }

    public object? LookupVariable(Token name, Expression expression)
    {
        if (Locals.TryGetValue(expression, out var depth))
        {
            return Environment.GetAt(depth, name.Lexeme);
        }
        return Globals.Get(name);
    }

    public static string Stringify(object? value)
    {
        return value?.ToString() ?? "nil";
    }

    public static bool IsTruthy(object? value)
    {
        return value switch
        {
            bool boolValue => boolValue,
            string stringValue => stringValue.Length > 0,
            _ => false,
        };
    }
}

abstract class Callable
{
    public abstract int Arity { get; }

    public abstract object? Call(Interpreter interpreter, List<object?> arguments);
}

class FuncCallable : Callable
{
    private readonly Func<Interpreter, List<object?>, object?> callable;
    private readonly int arity;

    public override int Arity => arity;

    public FuncCallable(Func<Interpreter, List<object?>, object?> callable, int arity)
    {
        this.callable = callable;
        this.arity = arity;
    }

    public override object? Call(Interpreter interpreter, List<object?> arguments)
    {
        return callable(interpreter, arguments);
    }

    public override string ToString()
    {
        return "<native fn>";
    }
}

class RuntimeFunction : Callable
{
    private readonly FunctionDeclaration declaration;
    private readonly Environment closure;
    private readonly bool isInitializer;

    public override int Arity => declaration.Parameters.Count;

    public RuntimeFunction(FunctionDeclaration declaration, Environment closure, bool isInitializer)
    {
        this.declaration = declaration;
        this.closure = closure;
        this.isInitializer = isInitializer;
    }

    public override object? Call(Interpreter interpreter, List<object?> arguments)
    {
        var environment = new Environment(closure);
        for (int i = 0; i < declaration.Parameters.Count; ++i)
        {
            environment.Define(declaration.Parameters[i].Lexeme, arguments[i]);
        }

        try
        {
            interpreter.ExecuteBlock(declaration.Body, environment);
        }
        catch (ReturnException exception)
        {
            return isInitializer ? closure.GetAt(0, "this") : exception.Value;
        }
        return null;
    }

    public RuntimeFunction Bind(RuntimeClassInstance instance)
    {
        var environment = new Environment(closure);
        environment.Define("this", instance);
        return new RuntimeFunction(declaration, environment, isInitializer);
    }
 
    public override string ToString()
    {
        return $"<fn {declaration.Name.Lexeme}>";
    }
}

class Resolver
{
    private readonly Interpreter interpreter;
    
    public readonly List<Dictionary<string, bool>> Scopes = new();

    public FunctionType CurrentFunction = FunctionType.None;
    public ClassType CurrentClass = ClassType.None;

    public Resolver(Interpreter interpreter)
    {
        this.interpreter = interpreter;
    }

    public void Resolve(List<Statement> statements)
    {
        foreach (var statement in statements)
        {
            statement.Resolve(this);
        }
    }

    public void BeginScope()
    {
        Scopes.Add(new());
    }

    public void EndScope()
    {
        Scopes.RemoveAt(Scopes.Count - 1);
    }

    public void Declare(Token name)
    {
        if (Scopes.Count > 0)
        {
            var scope = Scopes[^1];
            if (scope.ContainsKey(name.Lexeme))
            {
                Program.Error(name, "Already a variable with this name in this scope.");
            }

            Scopes[^1][name.Lexeme] = false;
        }
    }

    public void Define(Token name)
    {
        if (Scopes.Count > 0)
        {
            Scopes[^1][name.Lexeme] = true;
        }
    }

    public void ResolveLocal(Expression expression, Token name)
    {
        for (int i = Scopes.Count - 1; i >= 0; --i)
        {
            if (Scopes[i].ContainsKey(name.Lexeme))
            {
                interpreter.Resolve(expression, Scopes.Count - 1 - i);
            }
        }
    }

    public void ResolveFunction(FunctionDeclaration function, FunctionType type)
    {
        var enclosingFunction = CurrentFunction;
        CurrentFunction = type;

        BeginScope();
        foreach (var token in function.Parameters)
        {
            Declare(token);
            Define(token);
        }
        Resolve(function.Body);
        EndScope();

        CurrentFunction = enclosingFunction;
    }
}

enum FunctionType
{
    None,
    Function,
    Method,
    Initializer,
}

enum ClassType
{
    None,
    Class,
}