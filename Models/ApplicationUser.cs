using System.ComponentModel.DataAnnotations;

namespace LeopardApp.Models;

public class ApplicationUser
{
    public Guid Id { get; set; }

    [Required]
    [StringLength(50)]
    public string FirstName { get; set; }

    [Required]
    [StringLength(50)]
    public string LastName { get; set; }

    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [Phone]
    public string PhoneNumber { get; set; }

    public bool IsAdmin { get; set; }

    public bool IssueCertificate { get; set; } = true;

    public string PasswordHash { get; set; }

    public string CertificateSerialNumber { get; set; }

    public bool CertificateDownloaded { get; set; }

    public DateTime? CertificateIssuedAt { get; set; }

    public DateTime? CertificateExpiresAt { get; set; }

    public bool IsActive { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}