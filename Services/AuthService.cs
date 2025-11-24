using System.Security.Cryptography;
using System.Text;
using MySql.Data.MySqlClient;

public class AuthService
{
    private readonly DatabaseHelper _dbHelper;

    // PBKDF2 settings
    private const int SaltSize = 16; // bytes
    private const int KeySize = 32; // bytes
    private const int Iterations = 100_000;

    public AuthService(DatabaseHelper dbHelper)
    {
        _dbHelper = dbHelper;
    }

    public async Task<bool> RegisterUserAsync(string email, string password)
    {
        using var connection = await _dbHelper.GetConnectionAsync();

        // check existing
        using (var checkCommand = new MySqlCommand("SELECT id FROM users WHERE email=@Email", connection))
        {
            checkCommand.Parameters.AddWithValue("@Email", email);
            var existing = await checkCommand.ExecuteScalarAsync();
            if (existing != null) return false;
        }

        var saltedHash = CreateSaltedHash(password); // format: iterations.saltBase64.hashBase64

        using var insertCommand = new MySqlCommand(
            "INSERT INTO users (email, password_hash) VALUES (@Email,@PasswordHash)", connection);
        insertCommand.Parameters.AddWithValue("@Email", email);
        insertCommand.Parameters.AddWithValue("@PasswordHash", saltedHash);

        var result = await insertCommand.ExecuteNonQueryAsync();
        return result > 0;
    }

    public async Task<UserRecord?> ValidateUserAsync(string email, string password)
    {
        using var connection = await _dbHelper.GetConnectionAsync();

        using var cmd = new MySqlCommand(
            "SELECT id, email, password_hash, created_at FROM users WHERE email=@Email", connection);
        cmd.Parameters.AddWithValue("@Email", email);

        using var reader = await cmd.ExecuteReaderAsync();
        if (await reader.ReadAsync())
        {
            var user = new UserRecord
            {
                Id = reader.GetInt32(reader.GetOrdinal("id")),
                Email = reader.GetString(reader.GetOrdinal("email")),
                PasswordHash = reader.GetString(reader.GetOrdinal("password_hash")),
                CreatedAt = reader.GetDateTime(reader.GetOrdinal("created_at"))
            };

            if (VerifyPassword(password, user.PasswordHash))
            {
                // do not return password hash to callers later
                return user;
            }
        }

        return null;
    }

    public async Task<List<UserRecord>> GetAllUsersAsync()
    {
        var users = new List<UserRecord>();
        using var connection = await _dbHelper.GetConnectionAsync();

        using var command = new MySqlCommand("SELECT id, email, password_hash, created_at FROM users", connection);
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

    // ---------- PBKDF2 helpers ----------
    private string CreateSaltedHash(string password)
    {
        using var rng = RandomNumberGenerator.Create();
        var salt = new byte[SaltSize];
        rng.GetBytes(salt);

        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256);
        var key = pbkdf2.GetBytes(KeySize);

        // store as: iterations.salt.hash (base64)
        return $"{Iterations}.{Convert.ToBase64String(salt)}.{Convert.ToBase64String(key)}";
    }

    private bool VerifyPassword(string password, string stored)
    {
        try
        {
            var parts = stored.Split('.', 3);
            if (parts.Length != 3) return false;

            var iterations = int.Parse(parts[0]);
            var salt = Convert.FromBase64String(parts[1]);
            var storedKey = Convert.FromBase64String(parts[2]);

            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
            var key = pbkdf2.GetBytes(storedKey.Length);

            return CryptographicOperations.FixedTimeEquals(key, storedKey);
        }
        catch
        {
            return false;
        }
    }
}
