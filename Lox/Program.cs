class Program
{
    private static bool hadError = false;

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
        return hadError ? 65 : 0;
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

        // For now, just print the tokens.
        foreach (var token in tokens)
        {
            Console.WriteLine(token);
        }
    }

    public static void Error(int line, string message)
    {
        Report(line, "", message);
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
        var text = source.Substring(start, current - start);
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
        var value = source.Substring(start + 1, current - 1);
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

        AddToken(TokenType.Number, source.Substring(start, current - start));
    }

    private void Identifier()
    {
        while (IsAlphaNumeric(Peek()))
        {
            Advance();
        }

        var text = source.Substring(start, current - start);
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