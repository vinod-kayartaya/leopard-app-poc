using Microsoft.AspNetCore.Mvc;

namespace LeopardApp.Controllers;

public class HomeController : Controller
{
    public IActionResult Index()
    {
        if (User.Identity.IsAuthenticated)
        {
            if (User.IsInRole("Admin"))
                return RedirectToAction("Index", "Admin");
            else
                return RedirectToAction("Dashboard", "User");
        }

        return RedirectToAction("Login", "Account");
    }
}