//////////////////////////////////////////////////////////////////////
// TOOLS
//////////////////////////////////////////////////////////////////////
#tool "nuget:?package=GitVersion.CommandLine&prerelease"

using Path = System.IO.Path;
using IO = System.IO;
using Cake.Common.Tools;

//////////////////////////////////////////////////////////////////////
// ARGUMENTS
//////////////////////////////////////////////////////////////////////
var target = Argument("target", "Default");
var configuration = Argument("configuration", "Release");

///////////////////////////////////////////////////////////////////////////////
// GLOBAL VARIABLES
///////////////////////////////////////////////////////////////////////////////
var publishDir = "./publish";
var localPackagesDir = "../LocalPackages";
var artifactsDir = "./artifacts";
var assetDir = "./BuildAssets";
var solutionToBuild = "./source/OpenIDConnectAuthenticationProvider.sln";

var bin452 = "/bin/Release/net452/";
var binNetStd = "/bin/Release/netstandard1.3/";

var gitVersionInfo = GitVersion(new GitVersionSettings {
    OutputType = GitVersionOutput.Json
});

var nugetVersion = gitVersionInfo.NuGetVersion;

///////////////////////////////////////////////////////////////////////////////
// SETUP / TEARDOWN
///////////////////////////////////////////////////////////////////////////////
Setup(context =>
{
    if(BuildSystem.IsRunningOnTeamCity)
        BuildSystem.TeamCity.SetBuildNumber(gitVersionInfo.NuGetVersion);

    Information("Building Octopus.Server.Extensibility.Authentication.OpenIDConnect v{0}", nugetVersion);
});

Teardown(context =>
{
    Information("Finished running tasks.");
});

//////////////////////////////////////////////////////////////////////
//  PRIVATE TASKS
//////////////////////////////////////////////////////////////////////

Task("__Default")
    .IsDependentOn("__Clean")
    .IsDependentOn("__Restore")
    .IsDependentOn("__Build")
    .IsDependentOn("__Pack")
    .IsDependentOn("__Publish")
    .IsDependentOn("__CopyToLocalPackages");

Task("__Clean")
    .Does(() =>
{
    CleanDirectory(artifactsDir);
    CleanDirectory(publishDir);
    CleanDirectories("./source/**/bin");
    CleanDirectories("./source/**/obj");
});

Task("__Restore")
    .Does(() => {
		NuGetRestore(solutionToBuild);
		
		DotNetCoreRestore("source", new DotNetCoreRestoreSettings
		{
			ArgumentCustomization = args => args.Append($"/p:Version={nugetVersion}")
		});
	}
);

Task("__Build")
    .Does(() =>
{
    DotNetCoreBuild("./source", new DotNetCoreBuildSettings
    {
        Configuration = configuration,
        ArgumentCustomization = args => args.Append($"/p:Version={nugetVersion}")
    });
});

Task("__Pack")
    .Does(() => {
        var solutionDir = "./source/";
        
        // Server.Extensibility.Authentication.*
        
        var odNugetPackDir = Path.Combine(publishDir, "od");
        var nuspecFile = "Octopus.Server.Extensibility.Authentication.OpenIDConnect.nuspec";
            
        CreateDirectory(odNugetPackDir);
        CopyFileToDirectory(Path.Combine(assetDir, nuspecFile), odNugetPackDir);

        CopyFileToDirectory(solutionDir + "Server.Extensibility.Authentication.OpenIDConnect" + bin452 + "/Microsoft.IdentityModel.Logging.dll", odNugetPackDir);
        CopyFileToDirectory(solutionDir + "Server.Extensibility.Authentication.OpenIDConnect" + bin452 + "/Microsoft.IdentityModel.Tokens.dll", odNugetPackDir);
        CopyFileToDirectory(solutionDir + "Server.Extensibility.Authentication.OpenIDConnect" + bin452 + "/System.IdentityModel.Tokens.Jwt.dll", odNugetPackDir);
        CopyFileToDirectory(solutionDir + "Server.Extensibility.Authentication.OpenIDConnect" + bin452 + "Octopus.Node.Extensibility.Authentication.OpenIDConnect.dll", odNugetPackDir);
        CopyFileToDirectory(solutionDir + "Server.Extensibility.Authentication.OpenIDConnect" + bin452 + "Octopus.Server.Extensibility.Authentication.OpenIDConnect.dll", odNugetPackDir);
            
        CopyFileToDirectory(solutionDir + "Server.Extensibility.Authentication.AzureAD" + bin452 + "Octopus.Server.Extensibility.Authentication.AzureAD.dll", odNugetPackDir);
        CopyFileToDirectory(solutionDir + "Server.Extensibility.Authentication.GoogleApps" + bin452 + "Octopus.Server.Extensibility.Authentication.GoogleApps.dll", odNugetPackDir);
        CopyFileToDirectory(solutionDir + "Server.Extensibility.Authentication.Okta" + bin452 + "Octopus.Server.Extensibility.Authentication.Okta.dll", odNugetPackDir);

        NuGetPack(Path.Combine(odNugetPackDir, nuspecFile), new NuGetPackSettings {
            Version = nugetVersion,
            OutputDirectory = artifactsDir
        });

        DotNetCorePack("source/Client.Extensibility.Authentication.OpenIDConnect", new DotNetCorePackSettings
        {
            Configuration = configuration,
            OutputDirectory = artifactsDir,
            NoBuild = true,
            ArgumentCustomization = args => args.Append($"/p:Version={nugetVersion}")
        });
        
        DotNetCorePack("source/Client.Extensibility.Authentication.AzureAD", new DotNetCorePackSettings
        {
            Configuration = configuration,
            OutputDirectory = artifactsDir,
            NoBuild = true,
            ArgumentCustomization = args => args.Append($"/p:Version={nugetVersion}")
        });
            
        DotNetCorePack("source/Client.Extensibility.Authentication.GoogleApps", new DotNetCorePackSettings
        {
            Configuration = configuration,
            OutputDirectory = artifactsDir,
            NoBuild = true,
            ArgumentCustomization = args => args.Append($"/p:Version={nugetVersion}")
        });

        DotNetCorePack("source/Client.Extensibility.Authentication.Okta", new DotNetCorePackSettings
        {
            Configuration = configuration,
            OutputDirectory = artifactsDir,
            NoBuild = true,
            ArgumentCustomization = args => args.Append($"/p:Version={nugetVersion}")
        });
    });


Task("__Publish")
    .WithCriteria(BuildSystem.IsRunningOnTeamCity)
    .Does(() =>
{
    NuGetPush($"{artifactsDir}/Octopus.Server.Extensibility.Authentication.OpenIDConnect.{nugetVersion}.nupkg", new NuGetPushSettings {
        Source = "https://f.feedz.io/octopus-deploy/dependencies/nuget",
        ApiKey = EnvironmentVariable("FeedzIoApiKey")
    });

    NuGetPush($"{artifactsDir}/Octopus.Client.Extensibility.Authentication.AzureAD.{nugetVersion}.nupkg", new NuGetPushSettings {
        Source = "https://f.feedz.io/octopus-deploy/dependencies/nuget",
        ApiKey = EnvironmentVariable("FeedzIoApiKey")
    });

    NuGetPush($"{artifactsDir}/Octopus.Client.Extensibility.Authentication.GoogleApps.{nugetVersion}.nupkg", new NuGetPushSettings {
        Source = "https://f.feedz.io/octopus-deploy/dependencies/nuget",
        ApiKey = EnvironmentVariable("FeedzIoApiKey")
    });

    NuGetPush($"{artifactsDir}/Octopus.Client.Extensibility.Authentication.Okta.{nugetVersion}.nupkg", new NuGetPushSettings {
        Source = "https://f.feedz.io/octopus-deploy/dependencies/nuget",
        ApiKey = EnvironmentVariable("FeedzIoApiKey")
    });

    if (gitVersionInfo.PreReleaseLabel == "")
    {
        NuGetPush($"{artifactsDir}/Octopus.Client.Extensibility.Authentication.AzureAD.{nugetVersion}.nupkg", new NuGetPushSettings {
            Source = "https://www.nuget.org/api/v2/package",
                ApiKey = EnvironmentVariable("NuGetApiKey")
        });

        NuGetPush($"{artifactsDir}/Octopus.Client.Extensibility.Authentication.GoogleApps.{nugetVersion}.nupkg", new NuGetPushSettings {
            Source = "https://www.nuget.org/api/v2/package",
                ApiKey = EnvironmentVariable("NuGetApiKey")
        });

        NuGetPush($"{artifactsDir}/Octopus.Client.Extensibility.Authentication.Okta.{nugetVersion}.nupkg", new NuGetPushSettings {
            Source = "https://www.nuget.org/api/v2/package",
                ApiKey = EnvironmentVariable("NuGetApiKey")
        });
    }
});


Task("__CopyToLocalPackages")
    .WithCriteria(BuildSystem.IsLocalBuild)
    .IsDependentOn("__Pack")
    .Does(() =>
{
    CreateDirectory(localPackagesDir);
    CopyFileToDirectory(Path.Combine(artifactsDir, $"Octopus.Server.Extensibility.Authentication.OpenIDConnect.{nugetVersion}.nupkg"), localPackagesDir);
    CopyFileToDirectory(Path.Combine(artifactsDir, $"Octopus.Client.Extensibility.Authentication.AzureAD.{nugetVersion}.nupkg"), localPackagesDir);
    CopyFileToDirectory(Path.Combine(artifactsDir, $"Octopus.Client.Extensibility.Authentication.GoogleApps.{nugetVersion}.nupkg"), localPackagesDir);
    CopyFileToDirectory(Path.Combine(artifactsDir, $"Octopus.Client.Extensibility.Authentication.Okta.{nugetVersion}.nupkg"), localPackagesDir);
});

//////////////////////////////////////////////////////////////////////
// TASKS
//////////////////////////////////////////////////////////////////////
Task("Default")
    .IsDependentOn("__Default");

//////////////////////////////////////////////////////////////////////
// EXECUTION
//////////////////////////////////////////////////////////////////////
RunTarget(target);
