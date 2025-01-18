using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using LeopardApp.Services.Interfaces;
using Microsoft.Extensions.Logging;
using System;
using System.Security.Claims;

namespace LeopardApp.Controllers;

[Authorize]
public class UserController : Controller
{
    private readonly IUserService _userService;
    private readonly IEjbcaService _ejbcaService;
    private readonly ILogger<UserController> _logger;

    public UserController(IUserService userService, IEjbcaService ejbcaService, ILogger<UserController> logger)
    {
        _userService = userService;
        _ejbcaService = ejbcaService;
        _logger = logger;
    }

    public async Task<IActionResult> Dashboard()
    {
        var email = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;
        var user = await _userService.GetUserByEmailAsync(email);
        return View(user);
    }

    [HttpGet]
    public async Task<IActionResult> DownloadCertificate()
    {
        try
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var parsedId = Guid.Parse(userId);
            _logger.LogInformation(
                "User ID details - Raw: {RawId}, Parsed: {ParsedId}, Format D: {FormatD}",
                userId,
                parsedId,
                parsedId.ToString("D")
            );

            var user = await _userService.GetUserByIdAsync(parsedId);

            if (user == null)
            {
                _logger.LogWarning("User not found for ID: {UserId}", userId);
                return NotFound("User not found");
            }

            if (string.IsNullOrEmpty(user.CertificateSerialNumber))
            {
                _logger.LogWarning("No certificate found for user: {UserId}", userId);
                return NotFound("No certificate found");
            }

            var certificateBytes = await _ejbcaService.GetCertificateAsync(user.CertificateSerialNumber);

            // Update the download status
            user.CertificateDownloaded = true;
            await _userService.UpdateUserAsync(user);

            return File(
                certificateBytes,
                "application/x-pkcs12",
                $"certificate_{user.Email.Replace("@", "_")}.p12"
            );
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error downloading certificate");
            return RedirectToAction("Error", "Home", new { message = "Failed to download certificate. Please try again later." });
        }
    }

    [HttpGet]
    public IActionResult VerifyCertificate()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> VerifyCertificate(IFormFile certificate)
    {
        if (certificate == null)
        {
            ModelState.AddModelError("", "Please upload your certificate");
            return View();
        }

        using var ms = new MemoryStream();
        await certificate.CopyToAsync(ms);
        var certificateData = ms.ToArray();

        var isValid = await _ejbcaService.ValidateCertificateAsync(certificateData);
        if (!isValid)
        {
            _logger.LogWarning("Certificate validation failed for user {Email}. Certificate data length: {Length}",
                User.Identity.Name,
                certificateData?.Length ?? 0);
            ModelState.AddModelError("", "Invalid or expired certificate");
            return View();
        }

        _logger.LogInformation("Certificate successfully validated for user {Email}", User.Identity.Name);

        return RedirectToAction("Dashboard");
    }
}