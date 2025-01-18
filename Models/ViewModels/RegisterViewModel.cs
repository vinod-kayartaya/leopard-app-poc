using System.ComponentModel.DataAnnotations;

namespace LeopardApp.Models.ViewModels;

public class RegisterViewModel
{
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
}