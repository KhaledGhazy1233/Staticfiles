// ==================== DTOs ====================

namespace YourApp.DTOs
{
    // 1. DTO لإرسال الكود
    public class SendResetCodeDto
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }

    // 2. DTO للتحقق من الكود
    public class VerifyCodeDto
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [StringLength(6, MinimumLength = 6)]
        public string Code { get; set; }
    }

    // 3. DTO لإعادة تعيين الباسورد (فقط NewPassword و ConfirmPassword)
    public class ResetPasswordDto
    {
        [Required]
        [StringLength(100, MinimumLength = 6)]
        public string NewPassword { get; set; }

        [Required]
        [Compare("NewPassword")]
        public string ConfirmPassword { get; set; }
    }

    // Response للـ Verify Code
    public class VerifyCodeResponse
    {
        public string Message { get; set; }
        public string Token { get; set; }
        public string UserId { get; set; }
    }
}

// ==================== User Model ====================

namespace YourApp.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string PasswordResetCodeHash { get; set; }
        public DateTime? PasswordResetCodeExpiry { get; set; }
        public int PasswordResetAttempts { get; set; }
    }
}

// ==================== Service Interface ====================

namespace YourApp.Services.Interfaces
{
    public interface IAuthService
    {
        Task<string> SendResetPasswordCodeAsync(string email);
        Task<(bool success, string message, string token, string userId)> VerifyResetCodeAsync(string email, string code);
        Task<string> ResetPasswordAsync(string userId, string token, string newPassword);
    }
}

// ==================== Service Implementation ====================

namespace YourApp.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ApplicationDbContext _context;
        private readonly IEmailService _emailService;

        public AuthService(
            UserManager<ApplicationUser> userManager,
            ApplicationDbContext context,
            IEmailService emailService)
        {
            _userManager = userManager;
            _context = context;
            _emailService = emailService;
        }

        // ==================== 1. إرسال الكود ====================
        public async Task<string> SendResetPasswordCodeAsync(string email)
        {
            var trans = await _context.Database.BeginTransactionAsync();
            try
            {
                var user = await _userManager.FindByEmailAsync(email);
                if (user == null)
                    return "UserNotFound";

                // توليد كود 6 أرقام آمن
                var code = GenerateSecureCode();
                var codeHash = HashCode(code);

                user.PasswordResetCodeHash = codeHash;
                user.PasswordResetCodeExpiry = DateTime.UtcNow.AddMinutes(15);
                user.PasswordResetAttempts = 0;

                var result = await _userManager.UpdateAsync(user);
                if (!result.Succeeded)
                    return "ErrorInUpdateUser";

                var message = $"Code to reset password: {code}\nValid for 15 minutes.";
                await _emailService.SendEmail(user.Email, message, "Reset Password");

                await trans.CommitAsync();
                return "Success";
            }
            catch
            {
                await trans.RollbackAsync();
                return "Failed";
            }
        }

        // ==================== 2. التحقق من الكود ====================
        public async Task<(bool success, string message, string token, string userId)> VerifyResetCodeAsync(string email, string code)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(email);
                if (user == null)
                    return (false, "UserNotFound", null, null);

                // التحقق من انتهاء الصلاحية
                if (!user.PasswordResetCodeExpiry.HasValue || 
                    user.PasswordResetCodeExpiry.Value < DateTime.UtcNow)
                {
                    return (false, "CodeExpired", null, null);
                }

                // التحقق من عدد المحاولات
                if (user.PasswordResetAttempts >= 5)
                    return (false, "TooManyAttempts", null, null);

                // التحقق من الكود
                var codeHash = HashCode(code);
                if (user.PasswordResetCodeHash != codeHash)
                {
                    user.PasswordResetAttempts++;
                    await _userManager.UpdateAsync(user);
                    return (false, "InvalidCode", null, null);
                }

                // توليد token صالح لإعادة تعيين الباسورد
                var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);

                // مسح الكود بعد التحقق منه (يُستخدم مرة واحدة فقط)
                user.PasswordResetCodeHash = null;
                user.PasswordResetCodeExpiry = null;
                user.PasswordResetAttempts = 0;
                await _userManager.UpdateAsync(user);

                // إرجاع Token و UserId للاستخدام في الخطوة التالية
                return (true, "Success", resetToken, user.Id);
            }
            catch
            {
                return (false, "Failed", null, null);
            }
        }

        // ==================== 3. إعادة تعيين الباسورد ====================
        public async Task<string> ResetPasswordAsync(string userId, string token, string newPassword)
        {
            var trans = await _context.Database.BeginTransactionAsync();
            try
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user == null)
                    return "InvalidUser";

                // إعادة تعيين الباسورد باستخدام الـ token
                var result = await _userManager.ResetPasswordAsync(user, token, newPassword);
                if (!result.Succeeded)
                    return "PasswordResetFailed";

                // تنظيف أي بيانات متبقية (اختياري للأمان)
                user.PasswordResetCodeHash = null;
                user.PasswordResetCodeExpiry = null;
                user.PasswordResetAttempts = 0;
                await _userManager.UpdateAsync(user);

                await trans.CommitAsync();
                return "Success";
            }
            catch
            {
                await trans.RollbackAsync();
                return "Failed";
            }
        }

        // ==================== Helper Methods ====================
        private string GenerateSecureCode()
        {
            using var rng = RandomNumberGenerator.Create();
            var num = RandomNumberGenerator.GetInt32(0, 1_000_000);
            return num.ToString("D6");
        }

        private string HashCode(string code)
        {
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(code);
            var hash = sha256.ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }
    }
}

// ==================== Controller ====================

namespace YourApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        // ==================== 1. إرسال الكود ====================
        [HttpPost("send-reset-code")]
        public async Task<IActionResult> SendResetCode([FromBody] SendResetCodeDto dto)
        {
            if (!ModelState.IsValid)
                return BadRequest(new { message = "Invalid data" });

            var result = await _authService.SendResetPasswordCodeAsync(dto.Email);

            return result switch
            {
                "Success" => Ok(new { message = "Code sent to your email" }),
                "UserNotFound" => NotFound(new { message = "User not found" }),
                "ErrorInUpdateUser" => BadRequest(new { message = "Error updating user" }),
                _ => BadRequest(new { message = "Failed to send code" })
            };
        }

        // ==================== 2. التحقق من الكود ====================
        [HttpPost("verify-code")]
        public async Task<IActionResult> VerifyCode([FromBody] VerifyCodeDto dto)
        {
            if (!ModelState.IsValid)
                return BadRequest(new { message = "Invalid data" });

            var (success, message, token, userId) = await _authService.VerifyResetCodeAsync(dto.Email, dto.Code);

            if (!success)
            {
                return message switch
                {
                    "UserNotFound" => NotFound(new { message = "User not found" }),
                    "CodeExpired" => BadRequest(new { message = "Code has expired" }),
                    "TooManyAttempts" => BadRequest(new { message = "Too many failed attempts" }),
                    "InvalidCode" => BadRequest(new { message = "Invalid code" }),
                    _ => BadRequest(new { message = "Verification failed" })
                };
            }

            // إرجاع Token و UserId للمستخدم
            return Ok(new VerifyCodeResponse
            {
                Message = "Code verified successfully",
                Token = token,
                UserId = userId
            });
        }

        // ==================== 3. إعادة تعيين الباسورد ====================
        // المستخدم يرسل فقط: NewPassword و ConfirmPassword
        // الـ Token و UserId يتم إرسالهم في الـ Headers
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(
            [FromHeader(Name = "X-Reset-Token")] string resetToken,
            [FromHeader(Name = "X-User-Id")] string userId,
            [FromBody] ResetPasswordDto dto)
        {
            if (!ModelState.IsValid)
                return BadRequest(new { message = "Invalid data" });

            if (string.IsNullOrEmpty(resetToken) || string.IsNullOrEmpty(userId))
                return BadRequest(new { message = "Token and UserId are required" });

            var result = await _authService.ResetPasswordAsync(userId, resetToken, dto.NewPassword);

            return result switch
            {
                "Success" => Ok(new { message = "Password reset successfully" }),
                "InvalidUser" => NotFound(new { message = "User not found" }),
                "PasswordResetFailed" => BadRequest(new { message = "Failed to reset password. Check password requirements." }),
                _ => BadRequest(new { message = "Failed to reset password" })
            };
        }
    }
}

// ==================== في Program.cs ====================
// builder.Services.AddScoped<IAuthService, AuthService>();

/* 
==================== كيفية الاستخدام من Frontend ====================

// الخطوة 1: إرسال الكود للإيميل
POST /api/auth/send-reset-code
Body: { 
  "email": "user@example.com" 
}
Response: { "message": "Code sent to your email" }

// ------------------------------------------------

// الخطوة 2: التحقق من الكود
POST /api/auth/verify-code
Body: { 
  "email": "user@example.com", 
  "code": "123456" 
}
Response: { 
  "message": "Code verified successfully",
  "token": "CfDJ8KHG...",
  "userId": "abc123..."
}

// احفظ Token و UserId في Frontend (localStorage أو state)

// ------------------------------------------------

// الخطوة 3: إعادة تعيين الباسورد
// المستخدم يدخل فقط: NewPassword و ConfirmPassword
POST /api/auth/reset-password
Headers: {
  "X-Reset-Token": "CfDJ8KHG...",
  "X-User-Id": "abc123..."
}
Body: { 
  "newPassword": "NewPass@123",
  "confirmPassword": "NewPass@123"
}
Response: { "message": "Password reset successfully" }

==================== مثال على React/Angular ====================

// بعد verify-code
const { token, userId } = response.data;
localStorage.setItem('resetToken', token);
localStorage.setItem('resetUserId', userId);

// في صفحة Reset Password
const resetToken = localStorage.getItem('resetToken');
const userId = localStorage.getItem('resetUserId');

fetch('/api/auth/reset-password', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-Reset-Token': resetToken,
    'X-User-Id': userId
  },
  body: JSON.stringify({
    newPassword: 'NewPass@123',
    confirmPassword: 'NewPass@123'
  })
});

// بعد النجاح، امسح الـ token و userId
localStorage.removeItem('resetToken');
localStorage.removeItem('resetUserId');

==================== الأمان ====================
✅ المستخدم يدخل فقط NewPassword و ConfirmPassword
✅ الكود يُستخدم مرة واحدة فقط (يُمسح بعد التحقق)
✅ Token يُولد من Identity ويكون مرتبط بمستخدم محدد
✅ الكود صالح لمدة 15 دقيقة فقط
✅ حماية من Brute Force (5 محاولات فقط)
✅ Hash آمن للكود في قاعدة البيانات
*/
//public class EmailService : IEmailService
// {
//     private readonly EmailSettings _settings;
//     private readonly ILogger<EmailService> _logger;

//     public EmailService(
//         IOptions<EmailSettings> emailSettings,
//         ILogger<EmailService> logger)
//     {
//         _settings = emailSettings.Value;
//         _logger = logger;
//     }

//     public async Task<bool> SendEmailAsync(string email, string htmlMessage, string subject)
//     {
//         try
//         {
//             var message = new MimeMessage();
//             message.From.Add(
//                 new MailboxAddress(
//                     _settings.FromName ?? "Future Team",
//                     _settings.FromEmail));

//             message.To.Add(MailboxAddress.Parse(email));
//             message.Subject = subject ?? "Notification";

//             message.Body = new BodyBuilder
//             {
//                 HtmlBody = htmlMessage,
//                 TextBody = "Please view this message in HTML format."
//             }.ToMessageBody();

//             using var client = new SmtpClient();
//             client.Timeout = 10000;

//             await client.ConnectAsync(
//                 _settings.Host,
//                 _settings.Port,
//                 SecureSocketOptions.StartTls);

//             await client.AuthenticateAsync(
//                 _settings.FromEmail,
//                 _settings.Password);

//             await client.SendAsync(message);
//             await client.DisconnectAsync(true);

//             return true;
//         }
//         catch (Exception ex)
//         {
//             _logger.LogError(ex, "Email sending failed to {Email}", email);
//             return false;
//         }
//     }
// }

// Api
//  └── V1
//       └── TransactionType
//             ├── GetAll                → /Api/V1/TransactionType/GetAll
//             ├── GetById/{id}          → /Api/V1/TransactionType/GetById/{id}
//             ├── Create                → /Api/V1/TransactionType/Create
//             ├── Edit                  → /Api/V1/TransactionType/Edit
//             └── Delete/{id}           → /Api/V1/TransactionType/Delete/{id}

// Api
//  └── V1
//       └── Transaction
//             ├── GetAll                            → /Api/V1/Transaction/GetAll
//             ├── GetById/{id}                      → /Api/V1/Transaction/GetById/{id}
//             ├── GetByAccount/{accountNumber}      → /Api/V1/Transaction/GetByAccount/{accountNumber}
//             ├── Deposit                           → /Api/V1/Transaction/Deposit
//             ├── Withdraw                          → /Api/V1/Transaction/Withdraw
//             ├── Transfer                          → /Api/V1/Transaction/Transfer
//             └── GetStatement/{accountNumber}      → /Api/V1/Transaction/GetStatement/{accountNumber}


// Api
//  └── V1
//       └── AuditLog
//             ├── GetAll                        → /Api/V1/AuditLog/GetAll
//             ├── GetById/{id}                  → /Api/V1/AuditLog/GetById/{id}
//             ├── GetByUserId/{userId}          → /Api/V1/AuditLog/GetByUserId/{userId}
//             ├── GetByAccountId/{accountId}    → /Api/V1/AuditLog/GetByAccountId/{accountId}
//             └── Search                        → /Api/V1/AuditLog/Search   (optional)
