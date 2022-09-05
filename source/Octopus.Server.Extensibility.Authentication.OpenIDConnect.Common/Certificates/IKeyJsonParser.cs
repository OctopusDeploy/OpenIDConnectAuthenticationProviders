namespace Octopus.Server.Extensibility.Authentication.OpenIDConnect.Common.Certificates
{
    public interface IKeyJsonParser
    {
        KeyDetails[] Parse(string content);
    }
}