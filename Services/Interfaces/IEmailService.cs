namespace LeopardApp.Services.Interfaces;

public interface IEmailService
{
    Task SendPasswordSetupEmailAsync(string email, string resetLink);
    Task SendCertificateIssuedEmailAsync(string email);
}