using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using MySql.Data.MySqlClient;

// ---------------------------------------------------
// CONFIGURATION - UPDATED WITH CORS
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

// Register services
builder.Services.AddSingleton<DatabaseHelper>();
builder.Services.AddSingleton<AuthService>();

// ADD CORS CONFIGURATION - CRITICAL FIX
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// USE CORS - DAPAT NASA VERY TOP NG MIDDLEWARE
app.UseCors("AllowAll");

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseRouting();
app.UseAuthorization();

app.MapGet("/", () => "Backend is running!");
app.MapControllers();

app.Run();
// ---------------------------------------------------
// SINGLE FILE MODELS + DATABASE + SERVICE + CONTROLLER

// ===== MODELS =====
public class User
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class UserRecord
{
    public int Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
}

public class LoginResponse
{
    public bool Success { get; set; }
    public string Token { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
}

// ===== DATABASE HELPER =====
public class DatabaseHelper
{
    private readonly IConfiguration _configuration;
    private readonly string _connectionString;

    public DatabaseHelper(IConfiguration configuration)
    {
        _configuration = configuration;
        _connectionString = _configuration.GetConnectionString("DefaultConnection") ??
                            "Server=localhost;Database=aspnet_auth;Uid=root;Pwd=;SslMode=none;";
    }

    public async Task<MySqlConnection> GetConnectionAsync()
    {
        var connection = new MySqlConnection(_connectionString);
        await connection.OpenAsync();
        return connection;
    }

    public async Task CreateUsersTableAsync()
    {
        using var connection = await GetConnectionAsync();
        string sql = @"
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );";
        using var command = new MySqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync();
    }
}

// ===== AUTH SERVICE =====
public class AuthService
{
    private readonly DatabaseHelper _dbHelper;

    public AuthService(DatabaseHelper dbHelper)
    {
        _dbHelper = dbHelper;
    }

    public async Task<bool> RegisterUserAsync(string email, string password)
    {
        using var connection = await _dbHelper.GetConnectionAsync();

        var checkCommand = new MySqlCommand("SELECT id FROM users WHERE email=@Email", connection);
        checkCommand.Parameters.AddWithValue("@Email", email);
        var existingUser = await checkCommand.ExecuteScalarAsync();
        if (existingUser != null) return false;

        var passwordHash = HashPassword(password);

        var insertCommand = new MySqlCommand(
            "INSERT INTO users (email, password_hash) VALUES (@Email,@PasswordHash)", connection);
        insertCommand.Parameters.AddWithValue("@Email", email);
        insertCommand.Parameters.AddWithValue("@PasswordHash", passwordHash);

        var result = await insertCommand.ExecuteNonQueryAsync();
        return result > 0;
    }

    public async Task<UserRecord?> ValidateUserAsync(string email, string password)
    {
        using var connection = await _dbHelper.GetConnectionAsync();

        var command = new MySqlCommand(
            "SELECT id, email, password_hash, created_at FROM users WHERE email=@Email", connection);
        command.Parameters.AddWithValue("@Email", email);

        using var reader = await command.ExecuteReaderAsync();
        if (await reader.ReadAsync())
        {
            var user = new UserRecord
            {
                Id = reader.GetInt32(reader.GetOrdinal("id")),
                Email = reader.GetString(reader.GetOrdinal("email")),
                PasswordHash = reader.GetString(reader.GetOrdinal("password_hash")),
                CreatedAt = reader.GetDateTime(reader.GetOrdinal("created_at"))
            };

            if (VerifyPassword(password, user.PasswordHash)) return user;
        }

        return null;
    }

    public async Task<List<UserRecord>> GetAllUsersAsync()
    {
        var users = new List<UserRecord>();
        using var connection = await _dbHelper.GetConnectionAsync();

        var command = new MySqlCommand("SELECT id, email, password_hash, created_at FROM users", connection);

        using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            users.Add(new UserRecord
            {
                Id = reader.GetInt32(reader.GetOrdinal("id")),
                Email = reader.GetString(reader.GetOrdinal("email")),
                PasswordHash = reader.GetString(reader.GetOrdinal("password_hash")),
                CreatedAt = reader.GetDateTime(reader.GetOrdinal("created_at"))
            });
        }
        return users;
    }

    private string HashPassword(string password)
    {
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(password);
        var hash = sha256.ComputeHash(bytes);
        return Convert.ToBase64String(hash);
    }

    private bool VerifyPassword(string password, string storedHash)
    {
        return HashPassword(password) == storedHash;
    }
}

// ===== CONTROLLER =====
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly AuthService _authService;
    private readonly IConfiguration _configuration;
    private readonly DatabaseHelper _dbHelper;

    public AuthController(AuthService authService, IConfiguration configuration, DatabaseHelper dbHelper)
    {
        _authService = authService;
        _configuration = configuration;
        _dbHelper = dbHelper;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] User model)
    {
        await _dbHelper.CreateUsersTableAsync();
        var result = await _authService.RegisterUserAsync(model.Email, model.Password);
        if (result) return Ok(new { message = "User registered successfully" });
        return BadRequest(new { message = "User already exists" });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] User model)
    {
        var user = await _authService.ValidateUserAsync(model.Email, model.Password);
        if (user != null)
        {
            var token = GenerateJwtToken(user);
            return Ok(new LoginResponse
            {
                Success = true,
                Token = token,
                Email = user.Email,
                Message = "Login successful"
            });
        }
        return Unauthorized(new LoginResponse { Success = false, Message = "Invalid login attempt" });
    }

    [HttpGet("users")]
    public async Task<IActionResult> GetUsers()
    {
        await _dbHelper.CreateUsersTableAsync();
        var users = await _authService.GetAllUsersAsync();
        return Ok(users.Select(u => new { u.Id, u.Email, u.CreatedAt }));
    }

    private string GenerateJwtToken(UserRecord user)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim("userId", user.Id.ToString())
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"] ?? "fallback_secret_key_32_chars_long_12345"));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"] ?? "your_app",
            audience: _configuration["Jwt:Audience"] ?? "your_app",
            claims: claims,
            expires: DateTime.Now.AddHours(2),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}