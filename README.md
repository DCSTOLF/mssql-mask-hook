# mssql-mask-hook

## Hook
```
$Database = $env:VDB_DATABASE_NAME
$ServerInstance = $env:VDB_INSTANCE_HOST + "\" + $env:VDB_INSTANCE_NAME
$Environment = "Q800BCORP"
$RulesetName = "RS_" + $Database + "_con"
$ProfileJobName = "PR_JOB_" + $Database + "_con"
$MaskJobName = "MSK_JOB_" + $Database + "_con"
$ConnectorName = $Database + "_con"
$Log_File = "E:\delphix\scripts\log\" + $Environment + "\mssql_mask_hook_" + $Database + ".log"

cd E:\delphix\scripts

.\mssql_mask_hook.ps1 `
-SQLServer $ServerInstance `
-Database $Database `
-Engine maskengine01 `
-RulesetName $RulesetName `
-EnvName $Environment `
-OutputDir E:\delphix\scripts\outdir `
-DxmcPath E:\delphix\dxmc `
-ProfileJobName $ProfileJobName `
-ConnectorName $ConnectorName `
-MaskJobName $MaskJobName *>&1 | tee $Log_File

if ($lastExitCode -ne "0") {
  Write-Error "Error: mssql_mask_hook script failed!"
  exit 1
}
```
