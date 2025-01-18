using System.Net.Mail;
using LeopardApp.Services.Interfaces;
using Microsoft.Extensions.Configuration;
using System.Net;

namespace LeopardApp.Services;

public class EmailService : IEmailService
{
    private readonly IConfiguration _configuration;
    private readonly SmtpClient _smtpClient;

    public EmailService(IConfiguration configuration)
    {
        _configuration = configuration;
        _smtpClient = new SmtpClient(_configuration["EmailSettings:SmtpServer"])
        {
            Port = int.Parse(_configuration["EmailSettings:SmtpPort"]),
            Credentials = new NetworkCredential(
                _configuration["EmailSettings:SenderEmail"],
                _configuration["EmailSettings:SenderPassword"].Replace(" ", "")
            ),
            EnableSsl = true
        };
    }

    public async Task SendPasswordSetupEmailAsync(string toEmail, string resetLink)
    {
        try
        {
            var message = new MailMessage(
                _configuration["EmailSettings:SenderEmail"],
                toEmail,
                "Set Your Password - LeopardApp",
                $"Please click the following link to set your password: {resetLink}"
            );

            await _smtpClient.SendMailAsync(message);
            Console.WriteLine($"Password setup email sent to {toEmail}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to send password setup email: {ex.Message}");
            throw;
        }
    }

    public async Task SendCertificateIssuedEmailAsync(string email)
    {
        var smtpClient = new SmtpClient(_configuration["EmailSettings:SmtpServer"])
        {
            Port = int.Parse(_configuration["EmailSettings:SmtpPort"]),
            Credentials = new System.Net.NetworkCredential(
                _configuration["EmailSettings:SenderEmail"],
                _configuration["EmailSettings:SenderPassword"]
            ),
            EnableSsl = true,
        };

        var mailMessage = new MailMessage
        {
            From = new MailAddress(_configuration["EmailSettings:SenderEmail"]),
            Subject = "Your Certificate is Ready",
            Body = "Your certificate has been issued. Please log in to download it.",
            IsBodyHtml = true,
        };
        mailMessage.To.Add(email);

        await smtpClient.SendMailAsync(mailMessage);
    }
}