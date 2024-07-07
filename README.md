![logo](https://github.com/deannreid/The-Prober/assets/5481657/efaf7279-fba2-4034-84c4-5eadc4eb3a81)

## Description
**The Prober** aims to be an all-in-one enumeration tool, like the Pea but potentially cooler.

## Usage

### Parameters

- **SaveLocation**: Specifies the directory where results will be saved. Defaults to the current directory if not specified.
- **NoConfig**: Switch to disable the creation of the configuration file.
- **Version**: Displays the script version information.

### Examples

```powershell
.\pr0ber.ps1 -SaveLocation "C:\Scans" -NoConfig
```
Captures a variety of system information, saving results to the specified folder in separate files for each test and encodes the full output to B64 to easily get it off the box.

**Legal Disclaimer**: Don't be a dick. Only use this if you are legally allowed to do so.
