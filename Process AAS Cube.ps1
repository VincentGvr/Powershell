$server = "asazure://westeurope.asazure.windows.net/gennaker"
$database = "adventureworks"
$processType = "full"

$password = "Mdp" | ConvertTo-SecureString -asPlainText -Force
$username = "usrname"
$credential = New-Object System.Management.Automation.PSCredential($username,$password)
Invoke-ProcessASDatabase -Server $server -DatabaseName $database -RefreshType $processType -Credential $credential
