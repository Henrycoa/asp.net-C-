using MySql.Data.MySqlClient;

namespace backend.Models
{
    public class DatabaseHelper
    {
        private readonly IConfiguration _configuration;
        private readonly string _connectionString;

        public DatabaseHelper(IConfiguration configuration)
        {
            _configuration = configuration;
            _connectionString = _configuration.GetConnectionString("DefaultConnection")!;
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
}
