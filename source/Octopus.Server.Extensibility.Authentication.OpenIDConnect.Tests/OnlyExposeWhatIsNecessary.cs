using System;
using System.Linq;
using System.Reflection;
using Assent;
using NUnit.Framework;
using Octopus.Server.Extensibility.Authentication.AzureAD;
using Octopus.Server.Extensibility.Authentication.GoogleApps;
using Octopus.Server.Extensibility.Authentication.OctopusID;
using Octopus.Server.Extensibility.Authentication.Okta;

namespace Tests
{
    [TestFixture]
    public class OnlyExposeWhatIsNecessary
    {
        [Test]
        public void ServerExtensionsShouldMinimiseWhatIsExposed_AzureAD()
        {
            this.Assent(CheckAssembly(typeof(AzureADExtension).Assembly));
        }

        [Test]
        public void ServerExtensionsShouldMinimiseWhatIsExposed_GoogleApps()
        {
            this.Assent(CheckAssembly(typeof(GoogleAppsExtension).Assembly));
        }
        
        [Test]
        public void ServerExtensionsShouldMinimiseWhatIsExposed_Okta()
        {
            this.Assent(CheckAssembly(typeof(OktaExtension).Assembly));
        }
        
        [Test]
        public void ServerExtensionsShouldMinimiseWhatIsExposed_OctopusId()
        {
            this.Assent(CheckAssembly(typeof(OctopusIDExtension).Assembly));
        }

        string CheckAssembly(Assembly assembly)
        {
            var publicThings = assembly.GetExportedTypes()
                .Select(t => t.FullName);

            return string.Join(Environment.NewLine, publicThings);
        }
    }
}