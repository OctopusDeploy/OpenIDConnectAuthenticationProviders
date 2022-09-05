using System.Collections.Generic;
using System.Reflection;
using Octopus.Server.Extensibility.Extensions.Infrastructure.Web.Content;

namespace Octopus.Server.Extensibility.Authentication.GoogleApps.Web
{
    class GoogleAppsStaticContentFolders : IContributesStaticContentFolders
    {
        public IEnumerable<StaticContentEmbeddedResourcesFolder> GetStaticContentFolders()
        {
            var type = typeof(GoogleAppsStaticContentFolders);
            var assembly = type.GetTypeInfo().Assembly;
            return new [] { new StaticContentEmbeddedResourcesFolder("", assembly, type.Namespace + ".Static") };
        }
    }
}