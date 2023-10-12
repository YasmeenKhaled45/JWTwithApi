using System.ComponentModel.DataAnnotations;

namespace JWTRefreshTokenInDotNet6.Models
{
    public class RegisterModel
    {
        [MaxLength(100)]
        public string FirstName { get; set; }

        [MaxLength(100)]
        public string LastName { get; set; }

        [MaxLength(100)]
        public string Username { get; set; }

        [MaxLength(128)]
        public string Email { get; set; }

        [MaxLength(256)]
        public string Password { get; set; }
    }
}