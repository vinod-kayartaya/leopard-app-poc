using System.Security.Cryptography.X509Certificates;
using LeopardApp.Services.Interfaces;
using Microsoft.Extensions.Configuration;
using System.Net.Http;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace LeopardApp.Services;

public class EjbcaService : IEjbcaService
{
    private readonly IConfiguration _configuration;
    private readonly HttpClient _httpClient;
    private readonly ILogger<EjbcaService> _logger;
    private static readonly Dictionary<string, string> _certificateStore = new();
    private readonly IHttpContextAccessor _httpContextAccessor;

    public EjbcaService(
        IConfiguration configuration,
        IHttpClientFactory httpClientFactory,
        ILogger<EjbcaService> logger,
        IHttpContextAccessor httpContextAccessor)
    {
        _configuration = configuration;
        _httpClient = httpClientFactory.CreateClient("EjbcaClient");
        _logger = logger;
        _httpContextAccessor = httpContextAccessor;
    }

    private string GeneratePkcs10Request(string username, string email)
    {
        using (var rsa = RSA.Create(2048))
        {
            var subjectName = new X500DistinguishedName(
                $"CN={email}," +
                $"serialNumber=USER-{username}," +
                "O=LeopardApp," +
                $"E={email}"
            );

            var request = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            // Add enhanced key usage
            request.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    new OidCollection {
                        new Oid("1.3.6.1.5.5.7.3.2"),  // Client Authentication
                        new Oid("1.3.6.1.5.5.7.3.4"),  // Email Protection
                    },
                    true));

            // Add key usage
            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature |
                    X509KeyUsageFlags.KeyEncipherment |
                    X509KeyUsageFlags.DataEncipherment,
                    true));

            // Add Subject Alternative Name
            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddEmailAddress(email);
            request.CertificateExtensions.Add(sanBuilder.Build());

            var csr = request.CreateSigningRequest();
            return Convert.ToBase64String(csr);
        }
    }

    public async Task<(string SerialNumber, DateTime ExpiryDate)> IssueCertificateAsync(string userId, string email)
    {
        try
        {
            _logger.LogInformation("Attempting to issue certificate for user {Username} with email {Email}",
                userId, email);

            var certificateRequest = GeneratePkcs10Request(userId, email);

            var request = new
            {
                certificate_request = $"-----BEGIN CERTIFICATE REQUEST-----\n{certificateRequest}\n-----END CERTIFICATE REQUEST-----",
                certificate_profile_name = _configuration["Ejbca:CertificateProfile"],
                end_entity_profile_name = _configuration["Ejbca:EndEntityProfile"],
                certificate_authority_name = "ManagementCA",
                username = userId,
                password = "",  // Empty password as discussed
                include_chain = true
            };

            var content = new StringContent(
                JsonSerializer.Serialize(request),
                Encoding.UTF8,
                "application/json");

            _logger.LogInformation("Sending request to EJBCA: {RequestBody}",
                JsonSerializer.Serialize(request));

            var response = await _httpClient.PostAsync("/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll", content);
            var responseContent = await response.Content.ReadAsStringAsync();

            _logger.LogInformation("EJBCA Response: {StatusCode} - {Content}",
                response.StatusCode, responseContent);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError(
                    "EJBCA certificate issuance failed. Status: {Status}, Error: {Error}, Request: {@Request}",
                    response.StatusCode,
                    responseContent,
                    new { userId, email, certificateProfile = _configuration["Ejbca:CertificateProfile"] }
                );
                throw new Exception($"EJBCA request failed: {response.StatusCode} - {responseContent}");
            }

            var jsonResponse = JsonSerializer.Deserialize<JsonElement>(responseContent);
            if (jsonResponse.TryGetProperty("certificate", out var certElement))
            {
                var certString = certElement.GetString();
                var certBytes = Convert.FromBase64String(certString ?? string.Empty);
                var cert = new X509Certificate2(certBytes);

                // Store certificate in memory
                _certificateStore[cert.SerialNumber] = certString;
                _logger.LogInformation("Stored certificate with serial number: {SerialNumber}", cert.SerialNumber);

                return (SerialNumber: cert.SerialNumber, ExpiryDate: cert.NotAfter);
            }

            throw new Exception("Failed to parse certificate response");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error issuing certificate for user {Email}", email);
            throw;
        }
    }

    public async Task<byte[]> GetCertificateAsync(string serialNumber)
    {
        try
        {
            _logger.LogInformation("Attempting to download certificate with serial number: {SerialNumber}", serialNumber);

            if (_certificateStore.TryGetValue(serialNumber, out var certificateData))
            {
                try
                {
                    var certBytes = Convert.FromBase64String(certificateData);
                    using var cert = new X509Certificate2(certBytes);
                    _logger.LogInformation("Retrieved certificate from store. Subject: {Subject}", cert.Subject);
                    return certBytes;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error using stored certificate");
                }
            }

            var searchUrl = $"/ejbca/ejbca-rest-api/v1/certificate/search";
            var searchRequest = new
            {
                search_criteria = new[]
                {
                    new { property = "serialNumber", value = serialNumber, operation = "EQUALS" }
                },
                max_results = 1
            };

            var content = new StringContent(
                JsonSerializer.Serialize(searchRequest),
                Encoding.UTF8,
                "application/json");

            var response = await _httpClient.PostAsync(searchUrl, content);
            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                var jsonResponse = JsonSerializer.Deserialize<JsonElement>(responseContent);

                if (jsonResponse.TryGetProperty("certificates", out var certs) &&
                    certs.GetArrayLength() > 0)
                {
                    var certBase64 = certs[0].GetProperty("certificate").GetString();
                    return Convert.FromBase64String(certBase64);
                }
            }

            throw new Exception($"Failed to download certificate with serial number {serialNumber}");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting certificate for serial number {SerialNumber}", serialNumber);
            throw;
        }
    }

    public async Task<bool> ValidateCertificateAsync(byte[] certificateData)
    {
        try
        {
            // Get the current user's email from the claims
            var userEmail = _httpContextAccessor.HttpContext?.User?.FindFirstValue(ClaimTypes.Email);
            if (string.IsNullOrEmpty(userEmail))
            {
                _logger.LogWarning("No user email found in claims during certificate validation");
                return false;
            }

            // Load certificate without password
            var cert = new X509Certificate2(certificateData);

            _logger.LogInformation("Validating certificate: Subject={Subject}, Issuer={Issuer}, NotBefore={NotBefore}, NotAfter={NotAfter}",
                cert.Subject,
                cert.Issuer,
                cert.NotBefore,
                cert.NotAfter);

            // Basic validation
            if (DateTime.Now < cert.NotBefore || DateTime.Now > cert.NotAfter)
            {
                _logger.LogWarning("Certificate is outside its validity period");
                return false;
            }

            // Extract email from certificate subject
            var subjectDN = cert.Subject;
            var emailMatch = System.Text.RegularExpressions.Regex.Match(subjectDN, @"E=([^,]+)");
            if (!emailMatch.Success)
            {
                _logger.LogWarning("No email found in certificate subject: {Subject}", subjectDN);
                return false;
            }

            var certificateEmail = emailMatch.Groups[1].Value;

            // Verify the certificate belongs to the current user
            if (!string.Equals(certificateEmail, userEmail, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("Certificate email ({CertEmail}) does not match user email ({UserEmail})",
                    certificateEmail, userEmail);
                return false;
            }

            _logger.LogInformation("Certificate successfully validated for user {Email}", userEmail);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating certificate: {Message}", ex.Message);
            return false;
        }
    }

    public async Task<bool> CheckConnectionAsync()
    {
        try
        {
            var response = await _httpClient.GetAsync("/ejbca/ejbca-rest-api/v1/ca");
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "EJBCA health check failed");
            return false;
        }
    }
}