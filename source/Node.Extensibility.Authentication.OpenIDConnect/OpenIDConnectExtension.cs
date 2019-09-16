using Autofac;
using Octopus.Node.Extensibility.Authentication.OpenIDConnect.Infrastructure;
using Octopus.Node.Extensibility.Authentication.OpenIDConnect.Issuer;

namespace Octopus.Node.Extensibility.Authentication.OpenIDConnect
{
    public abstract class OpenIDConnectExtension
    {
        public virtual void Load(ContainerBuilder builder)
        {
            builder.RegisterType<PrincipalToUserResourceMapper>().As<IPrincipalToUserResourceMapper>().InstancePerDependency();
        }
    }
}