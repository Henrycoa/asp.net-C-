namespace LoginDemo.Models
{
    public class Response
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public string? Email { get; set; }
        public string? Token { get; set; }
    }
}
