namespace LeopardApp.Services.Interfaces;

public interface IEjbcaService
{
    Task<(string SerialNumber, DateTime ExpiryDate)> IssueCertificateAsync(string userId, string email);
    Task<byte[]> GetCertificateAsync(string serialNumber);
    Task<bool> ValidateCertificateAsync(byte[] certificateData);
    Task<bool> CheckConnectionAsync();
}