namespace Octopus.Server.Extensibility.Authentication.OctopusID
{
    static class StringExtensions
    {
        public static string WithTrailingSlash(this string uri)
        {
            return $"{uri.TrimEnd('/')}/";
        }
        
        public static string WithoutTrailingSlash(this string uri)
        {
            return uri.TrimEnd('/');
        }
    }
}