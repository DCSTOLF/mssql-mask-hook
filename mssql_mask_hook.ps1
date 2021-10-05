<# 
.SYNOPSIS 
Runs pre and post scripts and execute masking jobs

.DESCRIPTION 
This script performs the masking process in a fully automated way. Basically performing the 5 steps below:
  1. Performing the refresh of the ruleset and its metadata;
  2. Running the profile job;
  3. Disabling or deleting indexes, constraints, triggers and any other restrictions that may impact masking process;
  4. Running the masking job;
  5. Enabling or recreating the disabled or deleted objects in step 3.

.PARAMETER SQLServer 
Sql Server name that the scripts should be run on. If you have an instance name just use "SqlServer\InstansName". 

.PARAMETER Database 
Database name that the scripts should be run on.

.PARAMETER Engine 
Delphix Masking Engine Name from dxmc. Check: .\dxmc engine add --help for more information.

.PARAMETER RulesetName
Delphix Masking Engine Ruleset Name.

.PARAMETER EnvName
Delphix Masking Engine Environment Name.

.PARAMETER OutputDir
Output directory that temporary scripts will be create. 

.PARAMETER DxmcPath
Path location for DxToolkit for Masking binary. (https://github.com/delphix/dxm-toolkit)

.PARAMETER ProfileJobName
Profile job name that script will run it. 

.PARAMETER MaskJobName
Masking job name that script will run it. 

.PARAMETER ConnectorName
Connector name that script will run it. 

.PARAMETER ExecPreOnly
Execute only pre scripts.

.PARAMETER ExecPostOnly
Execute only post scripts. 

.PARAMETER SkipMasking
Do not execute the masking job.

.PARAMETER CustomFilterFile
Delimiter file containing metadata tables and customizable filter. Ex: mytable;where id is not null 

.PARAMETER removeUnmasked
Remove unmasked tables from inventory (useful for on-the-fly masking jobs)

.EXAMPLE 
.\mssql_mask_hook.ps1 `
      -SQLServer localhost `
      -Database Hooker `
      -Engine msk-engine `
      -RulesetName RS_HOOKER `
      -EnvName Hooker `
      -OutputDir C:\tmp `
      -DxmcPath C:\dxmc\bin `
      -ProfileJobName PR_JOB `
      -MaskJobName MSK_JOB `
      -ConnectorName MyConnector

.NOTES 
    File Name : mssql_mask_hook.ps1 
    Authors   : Paulo Maluf <paulo.maluf@experiortec.com>
                Eduardo Monte <eduardo.monte@experiortec.com>
#>

param  
(  
  [Parameter( 
    Position=1,
    Mandatory=$true, 
    ValueFromPipeline=$false, 
    ValueFromPipelineByPropertyName=$true) 
  ] 
  [string]$SQLServer='$env:computername\MSSQLSERVER',
    
  [Parameter( 
    Position=2,
    Mandatory=$true, 
    ValueFromPipeline=$false, 
    ValueFromPipelineByPropertyName=$true) 
  ] 
  [string]$Database,
    
  [Parameter( 
    Position=3,
    Mandatory=$true, 
    ValueFromPipeline=$false, 
    ValueFromPipelineByPropertyName=$true) 
  ] 
  [string]$Engine,
    
  [Parameter( 
    Position=4,
    Mandatory=$true, 
    ValueFromPipeline=$false, 
    ValueFromPipelineByPropertyName=$true) 
  ] 
  [string]$RulesetName,
    
  [Parameter( 
    Position=5,
    Mandatory=$true, 
    ValueFromPipeline=$false, 
    ValueFromPipelineByPropertyName=$true) 
  ] 
  [string]$EnvName,
    
  [Parameter( 
    Position=6,
    Mandatory=$true, 
    ValueFromPipeline=$false, 
    ValueFromPipelineByPropertyName=$true) 
  ] 
  [string]$OutputDir,
    
  [Parameter( 
    Position=7,
    Mandatory=$true, 
    ValueFromPipeline=$false, 
    ValueFromPipelineByPropertyName=$true) 
  ] 
  [string]$DxmcPath,
    
  [Parameter( 
    Position=8,
    Mandatory=$true, 
    ValueFromPipeline=$false, 
    ValueFromPipelineByPropertyName=$true) 
  ] 
  [string]$ProfileJobName,

  [Parameter( 
    Position=9,
    Mandatory=$true, 
    ValueFromPipeline=$false, 
    ValueFromPipelineByPropertyName=$true) 
  ] 
  [string]$MaskJobName,

  [Parameter( 
    Position=10,
    Mandatory=$true, 
    ValueFromPipeline=$false, 
    ValueFromPipelineByPropertyName=$true) 
  ] 
  [string]$ConnectorName,
    
  [Parameter( 
    Position=11,
    Mandatory=$false, 
    ValueFromPipeline=$false, 
    ValueFromPipelineByPropertyName=$true) 
  ] 
  [switch]$ExecPreOnly,
    
  [Parameter( 
    Position=12,
    Mandatory=$false, 
    ValueFromPipeline=$false, 
    ValueFromPipelineByPropertyName=$true) 
  ] 
  [switch]$ExecPostOnly,
    
  [Parameter( 
    Position=13,
    Mandatory=$false, 
    ValueFromPipeline=$false, 
    ValueFromPipelineByPropertyName=$true) 
  ] 
  [switch]$SkipMasking,

  [Parameter( 
    Position=14,
    Mandatory=$false, 
    ValueFromPipeline=$false, 
    ValueFromPipelineByPropertyName=$true) 
  ] 
  [string]$CustomFilterFile,

  [Parameter( 
    Position=15,
    Mandatory=$false, 
    ValueFromPipeline=$false, 
    ValueFromPipelineByPropertyName=$true) 
  ] 
  [switch]$removeUnmasked
)

# Function to handler error and exit
function die {
  Write-Error "Error: $($args[0])"
  exit 1
}

function check_connection(){
  SQLCMD -E -S $SQLServer -d $Database -Q "select @@servername" | Out-Null
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to estabilished connection on SQLServer. Parameters: $SqlParams"
  }
}

function export_inventory() {

  if ( $removeUnmasked ){
    & $dxmc column save --rulesetname $RulesetName --envname $EnvName --format csv --engine $engine --outputfile $OutputFile
  } 
  else {
    & $dxmc column save --rulesetname $RulesetName --envname $EnvName --is_masked --format csv --engine $engine --outputfile $OutputFile
  }

  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to export inventory file."
  }
}

function initialize_control_table(){
  SQLCMD -E -S $SQLServer -d $Database -Q "DROP TABLE IF EXISTS [dbo].[experior_targets];"
  
  SQLCMD -E -S $SQLServer -d $Database -Q "CREATE TABLE [dbo].[experior_targets](
               [Table_Name] [nvarchar](50)  NULL,
               [Type] [nvarchar](50) NULL,
               [Parent_Column_Name] [nvarchar](50)  NULL,
               [Column_Name] [nvarchar](50)  NULL,
               [Data_Type] [nvarchar](50) NULL,
               [Domain] [nvarchar](50)  NULL,
               [Algorithm] [nvarchar](50) NULL,
               [Is_Masked] [nvarchar](50) NULL,
               [ID_Method] [nvarchar](50) NULL,
               [Row_Type] [nvarchar](50) NULL,
               [Date_Format] [nvarchar](50) NULL
               ) ON [PRIMARY];" 
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to initilize the control table."
  }

  SQLCMD -E -S $SQLServer -d $Database -Q "bulk insert experior_targets from '$OutputFile' with (firstrow = 2, fieldterminator = ',',   rowterminator = '\n')"
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to initilize the control table."
  }
}

function create_enable_trigger_script(){
  SQLCMD -E -S $SQLServer -h -1 -d $Database -Q "SET NOCOUNT ON;
        SELECT DISTINCT ' ENABLE TRIGGER ['++SCHEMA_NAME(t2.[schema_id])++'].['++t1.[name]++'] ON ['++SCHEMA_NAME(t2.[schema_id])++'].['++t2.[name]++'];'
                 /*
                 SCHEMA_NAME(t2.[schema_id])
                 ,t2.[name] TableTriggerReference
                 , SCHEMA_NAME(t2.[schema_id]) TableSchemaName
                 , t1.[name] TriggerName
                 */
         FROM sys.triggers t1
                 INNER JOIN sys.tables t2 ON t2.object_id = t1.parent_id
          INNER JOIN dbo.experior_targets ET on ET.Table_Name = t2.name
         WHERE t1.is_disabled = 0" -o "$OutputDir\enable_trigger_$RulesetName.sql"
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to create the enable trigger script"
  }
}

function create_disable_trigger_script(){
   SQLCMD -E -S $SQLServer -h -1 -d $Database -Q "SET NOCOUNT ON;
   SELECT DISTINCT ' DISABLE TRIGGER ['++SCHEMA_NAME(t2.[schema_id])++'].['++t1.[name]++'] ON ['++SCHEMA_NAME(t2.[schema_id])++'].['++t2.[name]++'];'
               /*
               SCHEMA_NAME(t2.[schema_id])
               ,t2.[name] TableTriggerReference
               , SCHEMA_NAME(t2.[schema_id]) TableSchemaName
               , t1.[name] TriggerName
               */
    FROM sys.triggers t1
               INNER JOIN sys.tables t2 ON t2.object_id = t1.parent_id
        INNER JOIN dbo.experior_targets ET on ET.Table_Name = t2.name
    WHERE t1.is_disabled = 0" -o "$OutputDir\disable_trigger_$RulesetName.sql"
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to create the disable trigger script"
  }

}

function create_procedure_prepk(){
  SQLCMD -E -S $SQLServer -h -1 -d $Database -Q "create or alter procedure sp_experior_prepk
as
set nocount off;

DECLARE @object_id int;
DECLARE @parent_object_id int;
DECLARE @TSQL NVARCHAR(4000);
DECLARE @COLUMN_NAME SYSNAME;
DECLARE @is_descending_key bit;
DECLARE @col1 BIT;
DECLARE @action CHAR(6);
--SET @action = 'DROP';
SET @action = 'CREATE';
DECLARE PKcursor CURSOR FOR
    select distinct kc.object_id, kc.parent_object_id
    from sys.key_constraints kc
                               inner join sys.objects o on kc.parent_object_id = o.object_id
                               inner join dbo.experior_targets et on et.Table_Name = o.name
                where kc.type = 'PK' and o.type = 'U'
                               and et.Type LIKE 'PK%'
                               and o.name not in ('dtproperties','sysdiagrams');
OPEN PKcursor;
FETCH NEXT FROM PKcursor INTO @object_id, @parent_object_id;

WHILE @@FETCH_STATUS = 0
BEGIN
        SET @TSQL = 'ALTER TABLE '
                  + QUOTENAME(OBJECT_SCHEMA_NAME(@parent_object_id))
                  + '.' + QUOTENAME(OBJECT_NAME(@parent_object_id))
                  + ' ADD CONSTRAINT ' + QUOTENAME(OBJECT_NAME(@object_id))
                  + ' PRIMARY KEY'
                  + CASE INDEXPROPERTY(@parent_object_id
                                      ,OBJECT_NAME(@object_id),'IsClustered')
                        WHEN 1 THEN ' CLUSTERED'
                        ELSE ' NONCLUSTERED'
                    END
                  + ' (';
        DECLARE ColumnCursor CURSOR FOR
            select COL_NAME(@parent_object_id,ic.column_id), ic.is_descending_key
            from sys.indexes i
            inner join sys.index_columns ic
            on i.object_id = ic.object_id and i.index_id = ic.index_id
            where i.object_id = @parent_object_id
            and i.name = OBJECT_NAME(@object_id)
            order by ic.key_ordinal;
        OPEN ColumnCursor;
        SET @col1 = 1;
        FETCH NEXT FROM ColumnCursor INTO @COLUMN_NAME, @is_descending_key;
        WHILE @@FETCH_STATUS = 0
        BEGIN
            IF (@col1 = 1)
                SET @col1 = 0
            ELSE
                SET @TSQL = @TSQL + ',';
            SET @TSQL = @TSQL + QUOTENAME(@COLUMN_NAME)
                      + ' '
                      + CASE @is_descending_key
                            WHEN 0 THEN 'ASC'
                            ELSE 'DESC'
                        END;
            FETCH NEXT FROM ColumnCursor INTO @COLUMN_NAME, @is_descending_key;
        END;
        CLOSE ColumnCursor;
        DEALLOCATE ColumnCursor;
        SET @TSQL = @TSQL + ');';

    PRINT @TSQL;
    FETCH NEXT FROM PKcursor INTO @object_id, @parent_object_id;
END;
CLOSE PKcursor;
DEALLOCATE PKcursor;"
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to create the create procedure script"
  }
}

function create_rebuild_index_script(){
  SQLCMD -E -S $SQLServer -h -1 -d $Database -Q "SET NOCOUNT ON;
                               SELECT DISTINCT 'ALTER INDEX [' + I.name + '] ON [' +SCHEMA_NAME(T.[schema_id])+ '].[' + T.name + '] REBUILD;'
                                 FROM sys.indexes I
                               INNER JOIN sys.tables T on I.object_id = T.object_id
                               INNER JOIN dbo.experior_targets ET on ET.Table_Name = T.name
                               WHERE I.type_desc = 'NONCLUSTERED'
                                and I.name is not null
                                and I.is_primary_key = 0
                                and I.is_disabled = 0
                                and ET.Type like '%IX%'" -o "$OutputDir\rebuild_index_$RulesetName.sql"
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to create the rebuild index script"
  }
}

function create_disable_index_script(){
  SQLCMD -E -S $SQLServer -h -1 -d $Database -Q "SET NOCOUNT ON;
                             SELECT DISTINCT 'ALTER INDEX [' + I.name + '] ON [' +SCHEMA_NAME(T.[schema_id])+ '].[' + T.name + '] DISABLE;'
                               FROM sys.indexes I
                             INNER JOIN sys.tables T on I.object_id = T.object_id
                             INNER JOIN dbo.experior_targets ET on ET.Table_Name = T.name
                             WHERE I.type_desc = 'NONCLUSTERED'
                               and I.name is not null
                               and I.is_primary_key = 0
                               and I.is_disabled = 0
                               and ET.Type like '%IX%'" -o "$OutputDir\disable_index_$RulesetName.sql"
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to create the disable index script"
  }
}

function create_enable_constraint_script() {
  SQLCMD -E -S $SQLServer -h -1 -d $Database -Q "SET NOCOUNT ON;
                             SELECT distinct 'ALTER TABLE '++ QUOTENAME(OBJECT_SCHEMA_NAME(f.parent_object_id))++ '.' + QUOTENAME(OBJECT_NAME(f.parent_object_id))++ ' CHECK CONSTRAINT ALL;'
FROM
  sys.foreign_keys AS f
  INNER JOIN experior_targets as exp on exp.Table_Name = OBJECT_NAME(f.parent_object_id)
  INNER JOIN sys.foreign_key_columns AS fc ON f.OBJECT_ID = fc.constraint_object_id
  INNER JOIN sys.objects AS o ON o.OBJECT_ID = fc.referenced_object_id" -o "$OutputDir\enable_constraints_$RulesetName.sql"
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to create the enable constraint script"
  }
}

function create_disable_constraint_script() {
  SQLCMD -E -S $SQLServer -h -1 -d $Database -Q "SET NOCOUNT ON;
                            SELECT distinct 'ALTER TABLE '++ QUOTENAME(OBJECT_SCHEMA_NAME(f.parent_object_id))++ '.' + QUOTENAME(OBJECT_NAME(f.parent_object_id))++ ' NOCHECK CONSTRAINT ALL;'
FROM
  sys.foreign_keys AS f
  INNER JOIN experior_targets as exp on exp.Table_Name = OBJECT_NAME(f.parent_object_id)
  INNER JOIN sys.foreign_key_columns AS fc ON f.OBJECT_ID = fc.constraint_object_id
  INNER JOIN sys.objects AS o ON o.OBJECT_ID = fc.referenced_object_id" -o "$OutputDir\disable_constraints_$RulesetName.sql"
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to create the disable constraint script"
  }
}

function create_rebuild_table_script(){
  SQLCMD -E -S $SQLServer -h -1 -I -d $Database -Q "SET NOCOUNT ON;
    SELECT distinct 'ALTER TABLE '++ QUOTENAME(OBJECT_SCHEMA_NAME(f.parent_object_id))++ '.' + QUOTENAME(OBJECT_NAME(f.parent_object_id))++ ' REBUILD;'
      FROM
    sys.foreign_keys AS f
    INNER JOIN experior_targets as exp on exp.Table_Name = OBJECT_NAME(f.parent_object_id)
    INNER JOIN sys.foreign_key_columns AS fc ON f.OBJECT_ID = fc.constraint_object_id
    INNER JOIN sys.objects AS o ON o.OBJECT_ID = fc.referenced_object_id
    WHERE exp.Type is not null" -o "$OutputDir\rebuild_table_$RulesetName.sql"
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to create the rebuild table script"
  }
}

function create_drop_pk_script(){
  SQLCMD -E -S $SQLServer -h -1 -d $Database -Q "SET NOCOUNT ON;
                             SELECT DISTINCT 'ALTER TABLE '++ QUOTENAME(OBJECT_SCHEMA_NAME(kc.parent_object_id))++ '.' + QUOTENAME(OBJECT_NAME(kc.parent_object_id))++ ' DROP CONSTRAINT ' + QUOTENAME(OBJECT_NAME(kc.object_id)) + ';'
                               from sys.key_constraints kc
                              inner join sys.objects o on kc.parent_object_id = o.object_id
                              inner join dbo.experior_targets et on et.Table_Name = o.name
                              where kc.type = 'PK' and o.type = 'U'
                                and et.Type LIKE 'PK%';" -o "$OutputDir\drop_pk_$RulesetName.sql"
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to create the drop pk script"
  }
}

function create_pk_script(){
   SQLCMD -E -S $SQLServer -d $Database -Q "EXECUTE [dbo].[sp_experior_prepk]" -o "$OutputDir\create_pk_$RulesetName.sql"
   if( $LASTEXITCODE -ne 0 ) {
    die "Failed to create the create pk script"
  }
}


function create_drop_fk_script(){
  SQLCMD -E -S $SQLServer -h -1 -d $Database -Q "SET NOCOUNT ON
DECLARE @table TABLE(
  RowId INT PRIMARY KEY IDENTITY(1, 1),
  ForeignKeyConstraintName NVARCHAR(200),
  ForeignKeyConstraintTableSchema NVARCHAR(200),
  ForeignKeyConstraintTableName NVARCHAR(200),
  ForeignKeyConstraintColumnName NVARCHAR(200),
  PrimaryKeyConstraintName NVARCHAR(200),
  PrimaryKeyConstraintTableSchema NVARCHAR(200),
  PrimaryKeyConstraintTableName NVARCHAR(200),
  PrimaryKeyConstraintColumnName NVARCHAR(200)
  )
  INSERT INTO @table(ForeignKeyConstraintName, ForeignKeyConstraintTableSchema, ForeignKeyConstraintTableName, ForeignKeyConstraintColumnName)
  SELECT
  U.CONSTRAINT_NAME,
  U.TABLE_SCHEMA,
  U.TABLE_NAME,
  U.COLUMN_NAME
  FROM
  INFORMATION_SCHEMA.KEY_COLUMN_USAGE U
  INNER JOIN INFORMATION_SCHEMA.TABLE_CONSTRAINTS C
  ON U.CONSTRAINT_NAME = C.CONSTRAINT_NAME
  WHERE
  C.CONSTRAINT_TYPE = 'FOREIGN KEY'
  AND C.CONSTRAINT_NAME IN (SELECT DISTINCT RC.CONSTRAINT_NAME FROM 
  INFORMATION_SCHEMA.TABLE_CONSTRAINTS TC
  INNER JOIN dbo.experior_targets ET
  ON TC.TABLE_NAME = ET.Table_Name
  INNER JOIN INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS RC
  ON RC.UNIQUE_CONSTRAINT_NAME = TC.CONSTRAINT_NAME
  WHERE TC.CONSTRAINT_TYPE = 'PRIMARY KEY' 
    AND ET.Type is not null )
  
  UPDATE @table SET
  PrimaryKeyConstraintName = UNIQUE_CONSTRAINT_NAME
  FROM
  @table T
  INNER JOIN INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS R
  ON T.ForeignKeyConstraintName = R.CONSTRAINT_NAME
  
  UPDATE @table SET
  PrimaryKeyConstraintTableSchema = TABLE_SCHEMA,
  PrimaryKeyConstraintTableName = TABLE_NAME
  FROM @table T
  INNER JOIN INFORMATION_SCHEMA.TABLE_CONSTRAINTS C
  ON T.PrimaryKeyConstraintName = C.CONSTRAINT_NAME
  
  UPDATE @table SET
  PrimaryKeyConstraintColumnName = COLUMN_NAME
  FROM @table T
  INNER JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE U
  ON T.PrimaryKeyConstraintName = U.CONSTRAINT_NAME
  
  SELECT DISTINCT
  '
  ALTER TABLE [' + ForeignKeyConstraintTableSchema + '].[' + ForeignKeyConstraintTableName + ']
  DROP CONSTRAINT ' + ForeignKeyConstraintName + ';'
  FROM
  @table
  GO" -o "$OutputDir\drop_fk_$RulesetName.sql"
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to create the drop FK script"
  }
}

function create_fk_script(){
   SQLCMD -E -S $SQLServer -d $Database -y 512 -Y 512 -Q "SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;
SELECT N'
ALTER TABLE ' 
   + QUOTENAME(cs.name) + '.' + QUOTENAME(ct.name) 
   + ' ADD CONSTRAINT ' + QUOTENAME(fk.name) 
   + ' FOREIGN KEY (' + STUFF((SELECT ',' + QUOTENAME(c.name)
   -- get all the columns in the constraint table
    FROM sys.columns AS c 
    INNER JOIN sys.foreign_key_columns AS fkc 
    ON fkc.parent_column_id = c.column_id
    AND fkc.parent_object_id = c.[object_id]
    WHERE fkc.constraint_object_id = fk.[object_id]
    ORDER BY fkc.constraint_column_id 
    FOR XML PATH(N''), TYPE).value(N'.[1]', N'nvarchar(max)'), 1, 1, N'')
  + ') REFERENCES ' + QUOTENAME(rs.name) + '.' + QUOTENAME(rt.name)
  + '(' + STUFF((SELECT ',' + QUOTENAME(c.name)
   -- get all the referenced columns
    FROM sys.columns AS c 
    INNER JOIN sys.foreign_key_columns AS fkc 
    ON fkc.referenced_column_id = c.column_id
    AND fkc.referenced_object_id = c.[object_id]
    WHERE fkc.constraint_object_id = fk.[object_id]
    ORDER BY fkc.constraint_column_id 
    FOR XML PATH(N''), TYPE).value(N'.[1]', N'nvarchar(max)'), 1, 1, N'') + ');'
FROM sys.foreign_keys AS fk
INNER JOIN sys.tables AS rt -- referenced table
  ON fk.referenced_object_id = rt.[object_id]
INNER JOIN sys.schemas AS rs 
  ON rt.[schema_id] = rs.[schema_id]
INNER JOIN sys.tables AS ct -- constraint table
  ON fk.parent_object_id = ct.[object_id]
INNER JOIN sys.schemas AS cs 
  ON ct.[schema_id] = cs.[schema_id]
WHERE rt.is_ms_shipped = 0 AND ct.is_ms_shipped = 0 
  AND fk.name in (SELECT DISTINCT RC.CONSTRAINT_NAME FROM 
INFORMATION_SCHEMA.TABLE_CONSTRAINTS TC
INNER JOIN dbo.experior_targets ET
ON TC.TABLE_NAME = ET.Table_Name
INNER JOIN INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS RC
ON RC.UNIQUE_CONSTRAINT_NAME = TC.CONSTRAINT_NAME
WHERE TC.CONSTRAINT_TYPE = 'PRIMARY KEY'
  AND ET.Type is not null);" -o "$OutputDir\create_fk_$RulesetName.sql"
   if( $LASTEXITCODE -ne 0 ) {
    die "Failed to create the FK script"
  }
}

function exec_drop_fk(){
  SQLCMD -E -S $SQLServer -d $Database -i "$OutputDir\drop_fk_$RulesetName.sql"
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to execute the drop FK script"
  }
}

function exec_create_fk(){
  SQLCMD -E -S $SQLServer -d $Database -i "$OutputDir\create_fk_$RulesetName.sql"
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to execute the create FK script"
  }
}

function exec_disable_trigger(){
  SQLCMD -E -S $SQLServer -d $Database -i "$OutputDir\disable_trigger_$RulesetName.sql"
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to execute the disable trigger script"
  }
}

function exec_disable_constraint(){
  SQLCMD -E -S $SQLServer -d $Database -i "$OutputDir\disable_constraints_$RulesetName.sql"
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to execute the disable constraint script"
  }
}

function exec_disable_index(){
  SQLCMD -E -S $SQLServer -d $Database -i "$OutputDir\disable_index_$RulesetName.sql"
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to execute the disable index script"
  }
}

function exec_drop_pk(){
  SQLCMD -E -S $SQLServer -d $Database -i "$OutputDir\drop_pk_$RulesetName.sql"
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to execute the drop pk script"
  }
}

function exec_rebuild_table(){
  SQLCMD -E -S $SQLServer -d $Database -I -i "$OutputDir\rebuild_table_$RulesetName.sql"
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to execute the rebuild table script"
  }
}

function exec_enable_trigger(){
  SQLCMD -E -S $SQLServer -d $Database -i "$OutputDir\enable_trigger_$RulesetName.sql"
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to execute the enable trigger script"
  }
}

function exec_enable_constraint(){
  SQLCMD -E -S $SQLServer -d $Database -i "$OutputDir\enable_constraints_$RulesetName.sql"
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to execute the enable constraint script"
  }
}

function exec_rebuild_index(){
  SQLCMD -E -S $SQLServer -d $Database -i "$OutputDir\rebuild_index_$RulesetName.sql"
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to execute the rebuild index script"
  }
}

function exec_create_pk(){
  SQLCMD -E -S $SQLServer -d $Database -i "$OutputDir\create_pk_$RulesetName.sql" -I
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to execute the create pk script"
  }
}

function exec_mask_job(){
  
  Write-Host "Starting job: " -Foreground Green -NoNewline
  Write-Host $MaskJobName
  
  & $dxmc job start --envname $EnvName --engine $Engine --jobname $MaskJobName --tgt_connector $ConnectorName --tgt_connector_env $ConnectorName
  if( $LASTEXITCODE -ne 0 ) {
    die "Job finished unsuccessfully"
  } 
}

function exec_ruleset_refresh(){
  & $dxmc ruleset refresh --rulesetname $RulesetName --envname $EnvName --engine $Engine
}

function exec_ruleset_addmeta(){
  & $dxmc ruleset addmeta --rulesetname $RulesetName --envname $EnvName --engine $Engine --fromconnector --bulk
}

function exec_ruleset_remove_unmasked(){
    $tables=get_tables_from_metadata
    Foreach($table in $tables){ 
        $x =  & $dxmc  column list --envname $EnvName --engine $Engine --rulesetname $RulesetName --metaname $table --is_masked --format json | ConvertFrom-Json
        $columns=$x.'Column Name'
        if ($columns.count -eq 0){
            & $dxmc ruleset deletemeta --rulesetname $RulesetName --envname $EnvName --engine $Engine --metaname $table
        } 
    }
}

function add_custom_filter(){
  $Header = 'Metadata', 'Filter'
  $filters = Import-Csv -Delimiter ';' -Path $CustomFilterFile -Header $Header

  $filters | ForEach-Object {
    & $dxmc ruleset deletemeta --rulesetname $RulesetName --envname $EnvName --engine $Engine --metaname $_.Metadata
    & $dxmc ruleset addmeta --rulesetname $RulesetName --envname $EnvName --engine $Engine --metaname $_.Metadata --where_clause $_.Filter
  }

}

function exec_profile_job(){
  & $dxmc profilejob start --envname $EnvName --engine $Engine --jobname $ProfileJobName --tgt_connector $ConnectorName --tgt_connector_env $ConnectorName
  if( $LASTEXITCODE -ne 0 ) {
    Write-Host "Failed to execute the profile job" -Foreground Yellow
  }
}

function get_schema(){
  $x = & $dxmc connector list --envname $EnvName --engine $Engine --connectorname $ConnectorName --details --format json | ConvertFrom-Json
  if( $LASTEXITCODE -ne 0 ) {
    Write-Host "Failed to get connector details" -Foreground Yellow
  }
  $Schema = $x.'Schema Name'
  return $Schema
}

function get_tables_from_database(){
  $SchemaName = get_schema
  $tables = (SQLCMD -E -S $SQLServer -h -1 -d $Database -Q "SET NOCOUNT ON;
                                                 select RTRIM(LTRIM(t.name)) as table_name 
                                                   from sys.tables t
                                                  where schema_name(t.schema_id) = '$SchemaName'
                                                  order by table_name;")
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to get tables from $Database"
  }
  return $tables -replace '\s+', ''
}

function get_tables_from_metadata(){
  $x = & $dxmc ruleset listmeta --envname $EnvName --engine $Engine --rulesetname $RulesetName --format json | ConvertFrom-Json
  $tables = $x.'Metadata name' 
 
  return $tables
}

function get_missing_tables(){
  $database_tables = get_tables_from_database | sort
  $metadata_tables = get_tables_from_metadata | sort  
  
  Compare-Object -ReferenceObject $database_tables -DifferenceObject $metadata_tables -Passthru
}

function remove_missing_tables(){
  $tables = get_missing_tables

  Foreach($table in $tables){ 
    & $dxmc ruleset deletemeta --envname $EnvName --engine $Engine --rulesetname $RulesetName --metaname $table
  } 
}

function create_isolation_level_script(){
  SQLCMD -E -S $SQLServer -d $Database -Q "SET NOCOUNT ON;
  SELECT CASE  
          WHEN transaction_isolation_level = 1 
             THEN 'ALTER DATABASE [' + DB_NAME() + '] SET READ_UNCOMMITTED ON;' 
          WHEN transaction_isolation_level = 2 
               AND is_read_committed_snapshot_on = 1 
             THEN 'ALTER DATABASE [' + DB_NAME() + '] SET READ_COMMITTED_SNAPSHOT ON;' 
          WHEN transaction_isolation_level = 2 
               AND is_read_committed_snapshot_on = 0 THEN 'ALTER DATABASE [' + DB_NAME() + '] SET READ_COMMITTED_SNAPSHOT OFF;' 
          WHEN transaction_isolation_level = 3 
             THEN 'ALTER DATABASE [' + DB_NAME() + '] SET REPEATABLE_READ ON;' 
          WHEN transaction_isolation_level = 4 
             THEN 'ALTER DATABASE [' + DB_NAME() + '] SET SERIALIZABLE ON;' 
          WHEN transaction_isolation_level = 5 
             THEN 'ALTER DATABASE [' + DB_NAME() + '] SET SNAPSHOT ON;' 
          ELSE NULL
       END 
FROM   sys.dm_exec_sessions AS s
       CROSS JOIN sys.databases AS d
WHERE  session_id = @@SPID
  AND  d.database_id = DB_ID();"  -o "$OutputDir\isolation_level_$RulesetName.sql"
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to create the isolation level script" 
  }
}

function set_isolation_level(){
  SQLCMD -E -S $SQLServer -d $Database -Q "SET NOCOUNT ON;
  use [master];
  ALTER DATABASE [$Database] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
  ALTER DATABASE [$Database] SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE;
  ALTER DATABASE [$Database] SET MULTI_USER WITH NO_WAIT;
  ALTER DATABASE [$Database] SET DELAYED_DURABILITY = FORCED;"  
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to setting up the isolation level" 
  }
}

function restore_isolation_level(){
  SQLCMD -E -S $SQLServer -d $Database -i "$OutputDir\isolation_level_$RulesetName.sql"
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to restoring the isolation level"
  }
}

function set_compatibility_level(){
  SQLCMD -E -S $SQLServer -d $Database -Q "SET NOCOUNT ON;
  USE [dbamanage]
  DECLARE @SQL  NVARCHAR(MAX)
  SET @SQL = 'select ''ALTER DATABASE ''+ QUOTENAME(nm_database) +'' SET COMPATIBILITY_LEVEL = ''+ CAST(compatibility_level as NVARCHAR(30)) +'';'' 
              FROM dfx.databases 
			  WHERE nm_database = ''$Database'';'
  EXEC(@SQL)"
  if( $LASTEXITCODE -ne 0 ) {
    die "Failed to setting up the compatibility level"
  }
}

function Log($string, $color) {
  if($color -eq $null) { 
    $color = "White"
  }
  if(-Not (Test-Path ".\logs\$Database")) { 
    New-Item ".\logs\$Database" -type directory | out-null 
  }
  Write-Host $string -Foreground $color
  "$(get-date -Format 'dd-MM-yyyy hh:mm:ss'): $($string)" | Out-File .\logs\$Database\"$Database-$(Get-Date -Format dd-MM-yyyy).log" -Append -Encoding utf8 
}

function main(){
  $dxmc = "$DxmcPath\dxmc.exe"

  try {
    Test-Path -Path $dxmc -PathType Leaf | Out-Null
  }
  catch {
    die "Error: dxmc.exe not found!"
  }

  $DxmcParams = [ordered]@{
    '-SqlServer'      = $SQLServer
    '-Database'       = $Database
    '-RulesetName'    = $RulesetName
    '-EnvName'        = $EnvName
    '-OutputDir'      = $OutputDir
    '-Engine'         = $Engine
    '-DxmcPath'       = $DxmcPath
    '-ProfileJobName' = $ProfileJobName
    '-MaskJobName'    = $MaskJobName
    '-ExecPreOnly'    = $ExecPreOnly
    '-ExecPostOnly'   = $ExecPostOnly
    '-SkipMasking'    = $SkipMasking
    '-removeUnmasked' = $removeUnmasked
  }
  
  $OutputFile = "$OutputDir/$RulesetName.csv" 
  
  #Log "Parameters:" Green  
  #Log ($DxmcParams | Sort-Object -Property key | Out-String )
  
  check_connection
  
  $StartDate = Get-Date

  Log "Starting at $($StartDate)" Green

  if (($ExecPreOnly -eq $false) -And ($ExecPostOnly -eq $false)){
    $ExecPreOnly = $true
    $ExecPostOnly = $true 
  } 

  if ($ExecPreOnly -eq $true) {
    Log "[*] Executing ruleset refresh and addmeta" Green
    Log "Removing missing tables..."
    #remove_missing_tables
    Log "Executing ruleset add metadata..." 
    exec_ruleset_addmeta
    Log "Executing ruleset refresh..." 
    exec_ruleset_refresh

    if ($CustomFilterFile) {
      Log "Adding custom filters..."
      add_custom_filter
    }

    Log "[*] Setting up the isolation level" Green
    create_isolation_level_script
    set_isolation_level

    
    Log "[*] Executing profile job " Green
    exec_profile_job
    

    Log "[*] Export Inventory and Initializing Table" Green
    export_inventory
    initialize_control_table

    if ($removeUnmasked){
        Log "[*] Removing Unmasked Tables from Ruleset" Green
        exec_ruleset_remove_unmasked
    }
    
    Log "[*] Creating pre and post scripts" Green
    Log "- Create procedure script" 
    create_procedure_prepk
    
    Log "- Disable trigger script" 
    create_disable_trigger_script
    
    Log "- Enable trigger script"
    create_enable_trigger_script
    
    Log "- Drop FK script"
    create_drop_fk_script
    
    Log "- Create FK script"
    create_fk_script
    
    Log "- Disable constraint script"
    create_disable_constraint_script
    
    Log "- Enable constraint script"
    create_enable_constraint_script
    
    Log "- Disable index script"
    create_disable_index_script
    
    Log "- Rebuild index script"
    create_rebuild_index_script
    
    Log "- Rebuild table script"
    create_rebuild_table_script
    
    Log "- Drop PK script"
    create_drop_pk_script
    
    Log "- Create PK script"
    create_pk_script
    
    Log "[*] Executing pre-scripts" Green
    
    Log "- Executing disable trigger"
    exec_disable_trigger
    
    Log "- Executing disable constraint" 
    exec_disable_constraint
    
    Log "- Executing drop FK"
    exec_drop_fk

    Log "- Executing disable index"
    exec_disable_index
    
    Log "- Executing drop PK"
    exec_drop_pk

    #Log "- Executing rebuild table"
    #exec_rebuild_table

    Log "- Executing ruleset refresh"
    exec_ruleset_refresh

  }
  
  if ($SkipMasking -eq $true) {
    Log "[-] Skiping Masking Job" Yellow
  } 
  elseif ($SkipMasking -eq $false -and $ExecPreOnly -eq $true -and $ExecPostOnly -eq $true) {
    Log "[*] Executing Masking Jobs" Green
    exec_mask_job
  }
  
  if ($ExecPostOnly -eq $true) {
    Log "[*] Executing pos-scripts" Green
    
    Log "- Executing enable trigger"
    exec_enable_trigger

    Log "- Executing rebuild index"
    exec_rebuild_index

    Log "- Executing enable constraint"
    exec_enable_constraint
    
    Log "- Executing create PK"
    exec_create_pk

    Log "- Executing create FK"
    exec_create_fk

    Log "- Restoring the isolation level" 
    restore_isolation_level

    Log "- Setting the compatibility level" 
    set_compatibility_level | Out-Null
  }

  $EndDate = Get-Date

  Log "Execution completed." Green
  Log "Total Time: $($EndDate - $StartDate)" Green
}
main
