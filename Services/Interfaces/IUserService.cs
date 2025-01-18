namespace LeopardApp.Services.Interfaces;

public interface IUserService
{
    Task<ApplicationUser> CreateUserAsync(ApplicationUser user, string password);
    Task<ApplicationUser> GetUserByEmailAsync(string email);
    Task<bool> ValidatePasswordAsync(ApplicationUser user, string password);
    Task<IEnumerable<ApplicationUser>> GetAllUsersAsync();
    Task UpdateUserAsync(ApplicationUser user);
    Task DeleteUserAsync(Guid userId);
    Task SetPasswordAsync(string email, string password);
    Task<ApplicationUser> GetUserByIdAsync(Guid id);
}