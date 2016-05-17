

import-module 'F:\OneDrive for Business\Scripts\sql\SQL.psm1' -force

Set-SQLDBLoginRoles -ServerInstance jeffb-sql03 -databaseName test -Login stratuslivedemo\jeffbtest -DBRole db_datareader,db_datawriter -Verbose