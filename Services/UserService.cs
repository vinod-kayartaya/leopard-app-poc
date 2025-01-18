using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using LeopardApp.Data;
using LeopardApp.Models;
using LeopardApp.Services.Interfaces;
using Microsoft.Extensions.Logging;

namespace LeopardApp.Services;

public class UserService : IUserService
{
    private readonly ApplicationDbContext _context;
    private readonly IEmailService _emailService;
    private readonly IEjbcaService _ejbcaService;
    private readonly IConfiguration _configuration;
    private readonly ILogger<UserService> _logger;

    public UserService(
        ApplicationDbContext context,
        IEmailService emailService,
        IEjbcaService ejbcaService,
        IConfiguration configuration,
        ILogger<UserService> logger)
    {
        _context = context;
        _emailService = emailService;
        _ejbcaService = ejbcaService;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task<ApplicationUser> CreateUserAsync(ApplicationUser user, string password = null)
    {
        if (password != null)
        {
            user.PasswordHash = HashPassword(password);
            user.IsActive = true;
        }

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        if (user.IssueCertificate && !string.IsNullOrEmpty(_configuration["Ejbca:BaseUrl"]))
        {
            try
            {
                if (!await _ejbcaService.CheckConnectionAsync())
                {
                    throw new Exception("EJBCA server is not accessible");
                }

                _logger.LogInformation("Issuing certificate for user: {Email}", user.Email);

                var (serialNumber, expiryDate) = await _ejbcaService.IssueCertificateAsync(
                    user.Id.ToString(),
                    user.Email
                );

                _logger.LogInformation("Certificate issued. Serial: {Serial}, Expires: {Expiry}",
                    serialNumber, expiryDate);

                user.CertificateSerialNumber = serialNumber;
                user.CertificateIssuedAt = DateTime.UtcNow;
                user.CertificateExpiresAt = expiryDate;

                await _context.SaveChangesAsync();
                _logger.LogInformation("Updated user with certificate details: {Details}",
                    new { user.CertificateSerialNumber, user.CertificateIssuedAt, user.CertificateExpiresAt });

                await _emailService.SendCertificateIssuedEmailAsync(user.Email);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Certificate issuance failed for user: {Email}", user.Email);
            }
        }

        return user;
    }

    public async Task<ApplicationUser> GetUserByEmailAsync(string email)
    {
        return await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
    }

    public async Task<bool> ValidatePasswordAsync(ApplicationUser user, string password)
    {
        return await Task.Run(() => user.PasswordHash == HashPassword(password));
    }

    public async Task<IEnumerable<ApplicationUser>> GetAllUsersAsync()
    {
        return await _context.Users.ToListAsync();
    }

    public async Task UpdateUserAsync(ApplicationUser user)
    {
        user.UpdatedAt = DateTime.UtcNow;
        _context.Users.Update(user);
        await _context.SaveChangesAsync();
    }

    public async Task DeleteUserAsync(Guid userId)
    {
        var user = await _context.Users.FindAsync(userId);
        if (user != null)
        {
            _context.Users.Remove(user);
            await _context.SaveChangesAsync();
        }
    }

    public async Task SetPasswordAsync(string email, string password)
    {
        var user = await GetUserByEmailAsync(email);
        if (user != null)
        {
            user.PasswordHash = HashPassword(password);
            user.IsActive = true;
            user.UpdatedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();
        }
    }

    public async Task<ApplicationUser> GetUserByIdAsync(Guid id)
    {
        return await _context.Users.FindAsync(id);
    }

    private string HashPassword(string password)
    {
        using var sha256 = SHA256.Create();
        var hashedBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
        return Convert.ToBase64String(hashedBytes);
    }
}