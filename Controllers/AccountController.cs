using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using LeopardApp.Models.ViewModels;
using LeopardApp.Services.Interfaces;
using Microsoft.Extensions.Logging;

namespace LeopardApp.Controllers;

public class AccountController : Controller
{
    private readonly IUserService _userService;
    private readonly IEjbcaService _ejbcaService;
    private readonly ILogger<AccountController> _logger;

    public AccountController(IUserService userService, IEjbcaService ejbcaService, ILogger<AccountController> logger)
    {
        _userService = userService;
        _ejbcaService = ejbcaService;
        _logger = logger;
    }

    [HttpGet]
    public IActionResult Login()
    {
        if (User.Identity.IsAuthenticated)
            return RedirectToAction("Index", "Home");

        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        // Clear any existing authentication
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        foreach (var cookie in Request.Cookies.Keys)
        {
            Response.Cookies.Delete(cookie);
        }

        // Clear any existing certificate validation status
        HttpContext.Session.Remove("CertificateValidated");

        _logger.LogInformation("Login attempt for email: {Email}", model.Email);

        if (!ModelState.IsValid)
            return View(model);

        var user = await _userService.GetUserByEmailAsync(model.Email);
        _logger.LogInformation("Found user: {UserDetails}",
            new { user?.Id, user?.Email, user?.IsAdmin });

        if (user == null || !await _userService.ValidatePasswordAsync(user, model.Password))
        {
            ModelState.AddModelError("", "Invalid email or password");
            return View(model);
        }

        if (!user.IsActive)
        {
            ModelState.AddModelError("", "Account is not active");
            return View(model);
        }

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString("D")),
            new Claim(ClaimTypes.Role, user.IsAdmin ? "Admin" : "User")
        };

        _logger.LogInformation("Setting claims for user: {Email}, ID: {Id}, Claims: {@Claims}",
            user.Email, user.Id, claims);

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            new AuthenticationProperties
            {
                IsPersistent = model.RememberMe,
                ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1)
            }
        );

        _logger.LogInformation("User successfully logged in: {Email}", user.Email);

        if (user.IsAdmin)
            return RedirectToAction("Index", "Admin");

        if (!user.CertificateDownloaded && user.CertificateSerialNumber != null)
            return RedirectToAction("DownloadCertificate", "User");

        if (user.CertificateDownloaded)
            return RedirectToAction("Dashboard", "User");

        return RedirectToAction("VerifyCertificate", "User");
    }

    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        // Sign out of the authentication scheme
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        // Clear the existing cookie by setting it to expire immediately
        var cookieOptions = new CookieOptions
        {
            Expires = DateTime.Now.AddDays(-1),
            HttpOnly = true,
            Secure = true
        };

        // Clear all cookies
        foreach (var cookie in Request.Cookies.Keys)
        {
            Response.Cookies.Append(cookie, "", cookieOptions);
        }

        // Clear certificate validation status
        HttpContext.Session.Remove("CertificateValidated");

        // Clear session
        HttpContext.Session.Clear();

        _logger.LogInformation("User logged out and all cookies cleared");

        return RedirectToAction("Login");
    }

    [HttpGet]
    public IActionResult SetPassword(string email, string token)
    {
        var model = new SetPasswordViewModel
        {
            Email = email,
            Token = token
        };
        return View(model);
    }

    [HttpPost]
    public async Task<IActionResult> SetPassword(SetPasswordViewModel model)
    {
        if (!ModelState.IsValid)
            return View(model);

        // TODO: Validate token
        await _userService.SetPasswordAsync(model.Email, model.Password);
        return RedirectToAction("Login");
    }
}