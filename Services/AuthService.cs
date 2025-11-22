using MySql.Data.MySqlClient;
using System.Security.Cryptography;
using System.Text;
using backend.Models;

namespace backend.Services
{
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

            // Check if user already exists
            var checkCommand = new MySqlCommand("SELECT id FROM users WHERE email = @email", connection);
            checkCommand.Parameters.AddWithValue("@email", email);

            var existingUser = await checkCommand.ExecuteScalarAsync();
            if (existingUser != null)
            {
                return false; // User already exists
            }

            // Hash password
            var passwordHash = HashPassword(password);

            // Insert new user
            var insertCommand = new MySqlCommand(
                "INSERT INTO users (email, password_hash) VALUES (@email, @passwordHash)",
                connection);

            insertCommand.Parameters.AddWithValue("@email", email);
            insertCommand.Parameters.AddWithValue("@passwordHash", passwordHash);

            var result = await insertCommand.ExecuteNonQueryAsync();
            return result > 0;
        }

     public async Task<UserRecord?> ValidateUserAsync(string email, string password)
{
    using var connection = await _dbHelper.GetConnectionAsync();

    var command = new MySqlCommand(
        "SELECT id, email, password_hash, created_at FROM users WHERE email = @email",
        connection
    );
    command.Parameters.AddWithValue("@email", email);

    using var reader = await command.ExecuteReaderAsync();
    if (await reader.ReadAsync())
    {
        // Use GetOrdinal to get column index from column name
        int idIndex = reader.GetOrdinal("id");
        int emailIndex = reader.GetOrdinal("email");
        int passwordHashIndex = reader.GetOrdinal("password_hash");
        int createdAtIndex = reader.GetOrdinal("created_at");

        var user = new UserRecord
        {
            Id = reader.GetInt32(idIndex),
            Email = reader.GetString(emailIndex),
            PasswordHash = reader.GetString(passwordHashIndex),
            CreatedAt = reader.GetDateTime(createdAtIndex)
        };

        // Verify password
        if (VerifyPassword(password, user.PasswordHash))
        {
            return user;
        }
    }

    return null;
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
            var hash = HashPassword(password);
            return hash == storedHash;
        }
    }
}