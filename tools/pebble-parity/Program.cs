// Throwaway harness: exercises the existing .NET Acmebot.Acme AcmeClient against a
// locally running Pebble ACME CA (see .tools/pebble/scripts/start-pebble.sh), so its
// behavior can be compared side-by-side with the new Rust ACME client for the same
// domain/flow. See CONTEXT.md "Contract testing against a real ACME server".
//
// Prerequisites: Pebble + pebble-challtestsrv running locally
//   (.tools/pebble/scripts/start-pebble.sh), reachable at:
//     - https://127.0.0.1:14000/dir (ACME directory)
//     - http://127.0.0.1:8055     (challtestsrv management API for DNS-01 TXT records)
//
// Usage: dotnet run --project tools/pebble-parity -- <domain>
//   e.g. dotnet run --project tools/pebble-parity -- example.pebble

using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Acmebot.Acme;
using Acmebot.Acme.Models;

var domain = args.Length > 0 ? args[0] : "example.pebble";
var repoRoot = FindRepoRoot();
var setTxtScript = Path.Combine(repoRoot, ".tools", "pebble", "scripts", "set-txt.sh");
var clearTxtScript = Path.Combine(repoRoot, ".tools", "pebble", "scripts", "clear-txt.sh");

Console.WriteLine($"[.NET parity] Issuing certificate for '{domain}' against local Pebble CA");

// Pebble's TLS certificate (test/certs/localhost) is not trusted by the system store,
// so trust it explicitly for this harness only.
using var httpClientHandler = new HttpClientHandler
{
    ServerCertificateCustomValidationCallback = (_, _, _, _) => true
};
using var httpClient = new HttpClient(httpClientHandler);

using var client = new AcmeClient(httpClient, new Uri("https://127.0.0.1:14000/dir"));
using var accountSigner = AcmeSigner.CreateP256();

var account = await client.CreateAccountAsync(accountSigner, new AcmeNewAccountRequest
{
    Contact = ["mailto:admin@example.pebble"],
    TermsOfServiceAgreed = true
});
Console.WriteLine($"[.NET parity] Account: {account.AccountUrl}");

var orderResult = await client.CreateOrderAsync(account, [
    new AcmeIdentifier { Type = AcmeIdentifierTypes.Dns, Value = domain }
]);
var order = orderResult.Resource;
var orderUrl = orderResult.Location ?? throw new InvalidOperationException("The ACME server did not return an order URL.");
Console.WriteLine($"[.NET parity] Order status: {order.Status}");

foreach (var authorizationUrl in order.Authorizations)
{
    var authorizationResult = await client.GetAuthorizationAsync(account, authorizationUrl);
    var authorization = authorizationResult.Resource;

    var challenge = authorization.Challenges.First(c => c.Type == "dns-01");
    var keyAuthorization = $"{challenge.Token}.{accountSigner.GetThumbprint()}";
    var digest = SHA256.HashData(Encoding.ASCII.GetBytes(keyAuthorization));
    var txtValue = Base64UrlEncode(digest);

    RunScript(setTxtScript, domain, txtValue);
    Console.WriteLine($"[.NET parity] Set TXT for _acme-challenge.{domain} = {txtValue}");

    try
    {
        await client.AnswerChallengeAsync(account, challenge.Url);

        AcmeAuthorizationResource polled;
        do
        {
            await Task.Delay(TimeSpan.FromSeconds(1));
            polled = (await client.GetAuthorizationAsync(account, authorizationUrl)).Resource;
        }
        while (polled.Status == AcmeAuthorizationStatuses.Pending);

        if (polled.Status != AcmeAuthorizationStatuses.Valid)
        {
            throw new InvalidOperationException($"Authorization for {domain} ended in status '{polled.Status}'.");
        }

        Console.WriteLine($"[.NET parity] Authorization valid for {domain}");
    }
    finally
    {
        RunScript(clearTxtScript, domain);
    }
}

var (csrBytes, certificateKey) = CreateCsr(domain);

AcmeOrderResource finalizedOrder;
using (certificateKey)
{
    var finalizeResult = await client.FinalizeOrderAsync(account, order.Finalize!, csrBytes);
    finalizedOrder = finalizeResult.Resource;

    while (finalizedOrder.Status == AcmeOrderStatuses.Processing)
    {
        await Task.Delay(TimeSpan.FromSeconds(1));
        finalizedOrder = (await client.GetOrderAsync(account, orderUrl)).Resource;
    }
}

if (finalizedOrder.Status != AcmeOrderStatuses.Valid || finalizedOrder.Certificate is null)
{
    throw new InvalidOperationException($"Order for {domain} ended in status '{finalizedOrder.Status}' without a certificate URL.");
}

var certificateChain = await client.DownloadCertificateAsync(account, finalizedOrder.Certificate);
var outputPath = Path.Combine(repoRoot, "tools", "pebble-parity", $"{domain}.dotnet.pem");
await File.WriteAllTextAsync(outputPath, certificateChain.PemChain);

Console.WriteLine($"[.NET parity] Certificate issued ({certificateChain.Certificates.Count} cert(s) in chain), written to {outputPath}");
Console.WriteLine("[.NET parity] Done.");

static string FindRepoRoot()
{
    var dir = new DirectoryInfo(AppContext.BaseDirectory);
    while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Acmebot.slnx")))
    {
        dir = dir.Parent;
    }

    return dir?.FullName ?? throw new InvalidOperationException("Could not locate repo root (Acmebot.slnx not found).");
}

static void RunScript(string scriptPath, params string[] scriptArgs)
{
    var psi = new ProcessStartInfo("bash", [scriptPath, .. scriptArgs])
    {
        RedirectStandardOutput = true,
        RedirectStandardError = true
    };

    using var process = Process.Start(psi) ?? throw new InvalidOperationException($"Failed to start {scriptPath}");
    process.WaitForExit();

    if (process.ExitCode != 0)
    {
        throw new InvalidOperationException($"{scriptPath} exited with code {process.ExitCode}: {process.StandardError.ReadToEnd()}");
    }
}

static string Base64UrlEncode(byte[] data) =>
    Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

static (ReadOnlyMemory<byte> Csr, ECDsa Key) CreateCsr(string domain)
{
    var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var request = new CertificateRequest($"CN={domain}", key, HashAlgorithmName.SHA256);

    var sanBuilder = new SubjectAlternativeNameBuilder();
    sanBuilder.AddDnsName(domain);
    request.CertificateExtensions.Add(sanBuilder.Build());

    var csr = request.CreateSigningRequest();

    return (csr, key);
}
