using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using LeopardApp.Models;
using LeopardApp.Models.ViewModels;
using LeopardApp.Services.Interfaces;

namespace LeopardApp.Controllers;

[Authorize(Roles = "Admin")]
public class AdminController : Controller
{
    private readonly IUserService _userService;
    private readonly IEmailService _emailService;
    private readonly IConfiguration _configuration;

    public AdminController(
        IUserService userService,
        IEmailService emailService,
        IConfiguration configuration)
    {
        _userService = userService;
        _emailService = emailService;
        _configuration = configuration;
    }

    public async Task<IActionResult> Index()
    {
        var users = await _userService.GetAllUsersAsync();
        return View(users);
    }

    [HttpGet]
    public IActionResult Create()
    {
        return View(new RegisterViewModel());
    }

    [HttpPost]
    public async Task<IActionResult> Create(RegisterViewModel model)
    {
        if (!ModelState.IsValid)
            return View(model);

        var user = new ApplicationUser
        {
            FirstName = model.FirstName,
            LastName = model.LastName,
            Email = model.Email,
            PhoneNumber = model.PhoneNumber,
            IsAdmin = model.IsAdmin,
            IssueCertificate = model.IssueCertificate
        };

        // Create user with null password - password will be set via email link
        await _userService.CreateUserAsync(user, null);

        // Generate password reset token and send email
        var token = Convert.ToBase64String(Guid.NewGuid().ToByteArray());
        var resetLink = Url.Action("SetPassword", "Account",
            new { email = user.Email, token = token },
            Request.Scheme);

        await _emailService.SendPasswordSetupEmailAsync(user.Email, resetLink);

        return RedirectToAction(nameof(Index));
    }

    [HttpGet]
    public async Task<IActionResult> Edit(Guid id)
    {
        var user = await _userService.GetUserByEmailAsync(id.ToString());
        if (user == null)
            return NotFound();

        var model = new RegisterViewModel
        {
            FirstName = user.FirstName,
            LastName = user.LastName,
            Email = user.Email,
            PhoneNumber = user.PhoneNumber,
            IsAdmin = user.IsAdmin,
            IssueCertificate = user.IssueCertificate
        };

        return View(model);
    }

    [HttpPost]
    public async Task<IActionResult> Edit(Guid id, RegisterViewModel model)
    {
        if (!ModelState.IsValid)
            return View(model);

        var user = await _userService.GetUserByEmailAsync(id.ToString());
        if (user == null)
            return NotFound();

        user.FirstName = model.FirstName;
        user.LastName = model.LastName;
        user.Email = model.Email;
        user.PhoneNumber = model.PhoneNumber;
        user.IsAdmin = model.IsAdmin;
        user.IssueCertificate = model.IssueCertificate;

        await _userService.UpdateUserAsync(user);
        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    public async Task<IActionResult> Delete(Guid id)
    {
        await _userService.DeleteUserAsync(id);
        return RedirectToAction(nameof(Index));
    }
}