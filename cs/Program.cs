class Program
{
    static async Task Main(string[] args)
    {
        var options = ParseCommandLineArgs(args);
        
        if (options == null)
        {
            Console.WriteLine("Invalid command line arguments");
            return;
        }

        using var gpoOwned = new GPOwned(options);
        await gpoOwned.Execute();
    }

    private static GPOwnedOptions ParseCommandLineArgs(string[] args)
    {
        var options = new GPOwnedOptions();
        
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i].ToLower())
            {
                case "-gpoguid":
                case "-guid":
                    options.GPOGUID = args[++i].Trim('{', '}');
                    break;
                case "-scheduledtasksxmlpath":
                case "-xml":
                    options.ScheduledTasksXMLPath = args[++i];
                    break;
                case "-user":
                case "-u":
                    options.User = args[++i];
                    break;
                case "-author":
                case "-a":
                    options.Author = args[++i];
                    break;
                case "-domain":
                case "-d":
                    options.Domain = args[++i];
                    break;
                case "-computer":
                case "-c":
                    options.Computer = args[++i];
                    break;
                case "-help":
                case "-h":
                    options.Help = true;
                    break;
                case "-da":
                    options.DA = true;
                    break;
                case "-local":
                    options.Local = true;
                    break;
                case "-loaddll":
                case "-dll":
                    options.LoadDLL = args[++i];
                    break;
                case "-cmd":
                    options.CMD = args[++i];
                    break;
                case "-powershell":
                case "-ps":
                    options.PowerShell = args[++i];
                    break;
                case "-secondtaskxmlpath":
                case "-stx":
                    options.SecondTaskXMLPath = args[++i];
                    break;
                case "-log":
                    options.Log = args[++i];
                    break;
            }
        }

        return options;
    }
}