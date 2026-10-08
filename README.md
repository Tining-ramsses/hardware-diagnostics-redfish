# hardware-diagnostics-redfish
Pure Redfish implementation for Dell TSR and HPE AHS hardware diagnostic collection
Oui. J’ai revérifié les docs constructeur avant de te donner le code. Je corrige aussi un point important de mes réponses précédentes : pour Dell, le Redfish documenté ExportTechSupportReport dépose directement le ZIP sur un partage CIFS/NFS ; ce n’est pas un endpoint générique qui télécharge toujours le ZIP depuis l’iDRAC. Dell documente bien l’action et ses paramètres. 

Pour HPE, le workflow Redfish est différent : on découvre HpeiLOActiveHealthSystem, on récupère le lien AHS, puis le GET retourne le fichier binaire. 

Voici donc une V1 propre, 100 % Redfish, sans RACADM/iLOREST.

Fonction PowerShell

function Get-HardwareDiagnostic {
    [CmdletBinding()]
    param (
        # IP ou DNS de l'iDRAC / iLO
        [Parameter(Mandatory = $true)]
        [string]$ManagementAddress,
        # Compte iDRAC / iLO
        [Parameter(Mandatory = $true)]
        [PSCredential]$ManagementCredential,
        # Partage SMB, par exemple \\BMAAS-SRV\Diagnostics
        [Parameter(Mandatory = $true)]
        [string]$DestinationShare,
        # Compte permettant d'écrire dans le partage SMB
        # Pour Dell, ces identifiants sont transmis à l'iDRAC
        [Parameter(Mandatory = $false)]
        [PSCredential]$ShareCredential,
        # Nombre de jours AHS à télécharger côté HPE
        [Parameter(Mandatory = $false)]
        [ValidateRange(1,3650)]
        [int]$AhsDays = 30,
        # Ignorer les certificats auto-signés des iDRAC/iLO
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck
    )
    $ErrorActionPreference = "Stop"
    # ------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------
    function Write-DiagLog {
        param(
            [string]$Level,
            [string]$Message
        )
        $prefix = switch ($Level) {
            "INFO" { "[INFO]" }
            "OK"   { "[ OK ]" }
            "WARN" { "[WARN]" }
            "ERROR"{ "[ERROR]" }
            default { "[----]" }
        }
        Write-Host "$prefix $Message"
    }
    function Get-BasicAuthHeader {
        param(
            [PSCredential]$Credential
        )
        $plain = "{0}:{1}" -f `
            $Credential.UserName,
            $Credential.GetNetworkCredential().Password
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($plain)
        return @{
            Authorization = "Basic " + `
                [Convert]::ToBase64String($bytes)
        }
    }
    function Invoke-RedfishRequest {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Uri,
            [Parameter(Mandatory = $true)]
            [ValidateSet("GET","POST","PATCH","DELETE")]
            [string]$Method,
            [PSCredential]$Credential,
            [object]$Body,
            [switch]$Binary,
            [string]$OutFile
        )
        $headers = Get-BasicAuthHeader -Credential $Credential
        $params = @{
            Uri         = $Uri
            Method      = $Method
            Headers     = $headers
            ErrorAction = "Stop"
        }
        if ($SkipCertificateCheck) {
            if ($PSVersionTable.PSVersion.Major -ge 7) {
                $params.SkipCertificateCheck = $true
            }
        }
        if ($null -ne $Body) {
            $params.ContentType = "application/json"
            $params.Body = ($Body | ConvertTo-Json -Depth 20)
        }
        if ($Binary -and $OutFile) {
            $params.OutFile = $OutFile
        }
        return Invoke-WebRequest @params
    }
    function Get-RedfishJson {
        param(
            [string]$Uri,
            [PSCredential]$Credential
        )
        $response = Invoke-RedfishRequest `
            -Uri $Uri `
            -Method GET `
            -Credential $Credential
        return ($response.Content | ConvertFrom-Json)
    }
    # ------------------------------------------------------------
    # HTTPS certificate handling - PowerShell 5.1
    # ------------------------------------------------------------
    $oldCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    if ($SkipCertificateCheck -and
        $PSVersionTable.PSVersion.Major -lt 7) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
            return $true
        }
    }
    try {
        $BaseUri = "https://$ManagementAddress"
        Write-DiagLog INFO "Redfish endpoint : $BaseUri"
        # --------------------------------------------------------
        # 1. REDFISH ROOT DISCOVERY
        # --------------------------------------------------------
        $root = Get-RedfishJson `
            -Uri "$BaseUri/redfish/v1/" `
            -Credential $ManagementCredential
        Write-DiagLog OK "Redfish accessible"
        # --------------------------------------------------------
        # 2. IDENTIFICATION CONSTRUCTEUR
        # --------------------------------------------------------
        $systemUri = $null
        $managerUri = $null
        if ($root.Systems.'@odata.id') {
            $systemUri = $root.Systems.'@odata.id'
        }
        if ($root.Managers.'@odata.id') {
            $managerUri = $root.Managers.'@odata.id'
        }
        if (-not $managerUri) {
            throw "La ressource Redfish Managers n'est pas exposée."
        }
        # Récupération du premier Manager
        $managerCollection = Get-RedfishJson `
            -Uri "$BaseUri$managerUri" `
            -Credential $ManagementCredential
        $managerMember = $managerCollection.Members[0].'@odata.id'
        if (-not $managerMember) {
            throw "Impossible de découvrir le Manager Redfish."
        }
        $manager = Get-RedfishJson `
            -Uri "$BaseUri$managerMember" `
            -Credential $ManagementCredential
        $manufacturer = $manager.Manufacturer
        Write-DiagLog INFO "Manufacturer      : $manufacturer"
        Write-DiagLog INFO "Manager Model     : $($manager.Model)"
        Write-DiagLog INFO "Firmware          : $($manager.FirmwareVersion)"
        # ========================================================
        # DELL
        # ========================================================
        if ($manufacturer -match "Dell") {
            Write-DiagLog INFO "Dell controller detected"
            # ----------------------------------------------------
            # Vérification de la ressource DellLCService
            # ----------------------------------------------------
            $dellLcUri =
                "/redfish/v1/Dell/Managers/iDRAC.Embedded.1/DellLCService"
            try {
                $dellLc = Get-RedfishJson `
                    -Uri "$BaseUri$dellLcUri" `
                    -Credential $ManagementCredential
            }
            catch {
                Write-DiagLog WARN `
                    "DellLCService non accessible via Redfish."
                throw "Unsupported: ce contrôleur/firmware n'expose pas DellLCService via Redfish."
            }
            Write-DiagLog OK "DellLCService discovered"
            # ----------------------------------------------------
            # Endpoint OFFICIEL Dell
            # ----------------------------------------------------
            $actionUri =
                "$BaseUri/redfish/v1/Dell/Managers/" +
                "iDRAC.Embedded.1/DellLCService/Actions/" +
                "DellLCService.ExportTechSupportReport"
            # ----------------------------------------------------
            # Vérification de l'action
            # ----------------------------------------------------
            $actionAvailable = $false
            try {
                $action = Get-RedfishJson `
                    -Uri $actionUri `
                    -Credential $ManagementCredential
                $actionAvailable = $true
            }
            catch {
                # Certaines implémentations ne permettent pas
                # GET directement sur l'ActionInfo.
                # On ne considère PAS cela comme une preuve
                # que l'action n'existe pas.
                $actionAvailable = $true
            }
            # ----------------------------------------------------
            # Destination CIFS
            # ----------------------------------------------------
            if (-not $ShareCredential) {
                throw "ShareCredential est obligatoire pour l'export Dell CIFS."
            }
            $shareUser = $ShareCredential.UserName
            $sharePassword =
                $ShareCredential.GetNetworkCredential().Password
            # Exemple :
            # \\SERVER\Share\Diagnostics
            #
            # Dell attend ShareName comme nom/chemin du partage.
            #
            # On sépare serveur + partage.
            if ($DestinationShare -notmatch '^\\\\([^\\]+)\\([^\\]+)(.*)$') {
                throw "DestinationShare doit être au format \\SERVER\SHARE\OPTIONAL_PATH"
            }
            $shareServer = $Matches[1]
            $shareName   = $Matches[2]
            $subPath     = $Matches[3]
            $fileName =
                "TSR_{0}_{1}.zip" -f `
                $ManagementAddress.Replace(".","-"),
                (Get-Date -Format "yyyyMMdd_HHmmss")
            if ($subPath) {
                $relativeSharePath =
                    ($subPath.Trim("\") + "\" + $fileName)
            }
            else {
                $relativeSharePath = $fileName
            }
            # ----------------------------------------------------
            # Data selectors officiellement documentés
            # ----------------------------------------------------
            $selectors = @(
                "HWData",
                "OSAppData",
                "TTYLogs"
            )
            $body = @{
                ShareType          = "CIFS"
                DataSelectorArrayIn = ($selectors -join ",")
                IPAddress          = $shareServer
                ShareName          = $shareName
                UserName           = $shareUser
                Password           = $sharePassword
                FileName           = $relativeSharePath
            }
            Write-DiagLog INFO "Starting Dell TSR collection"
            Write-DiagLog INFO "Destination       : $DestinationShare"
            Write-DiagLog INFO "File              : $fileName"
            # ----------------------------------------------------
            # POST Redfish
            # ----------------------------------------------------
            $response = Invoke-RedfishRequest `
                -Uri $actionUri `
                -Method POST `
                -Credential $ManagementCredential `
                -Body $body
            Write-DiagLog OK "Dell TSR request accepted"
            # ----------------------------------------------------
            # Résultat du job
            # ----------------------------------------------------
            $jobId = $null
            if ($response.Content) {
                try {
                    $jobResponse =
                        $response.Content | ConvertFrom-Json
                    $jobId = $jobResponse.Job
                }
                catch {
                    # Certaines versions peuvent retourner
                    # une réponse sans JSON exploitable.
                }
            }
            if ($jobId) {
                Write-DiagLog INFO "Dell Job : $jobId"
            }
            # ----------------------------------------------------
            # Attente de la génération
            #
            # IMPORTANT :
            # Le POST Dell documenté réalise l'export vers le
            # partage CIFS. On vérifie donc ensuite que le fichier
            # apparaît réellement sur le partage.
            # ----------------------------------------------------
            $destinationRoot = $DestinationShare.TrimEnd("\")
            $expectedFile = Join-Path `
                $destinationRoot `
                $fileName
            $timeoutSeconds = 1800
            $elapsed = 0
            Write-DiagLog INFO "Waiting for TSR file..."
            while ($elapsed -lt $timeoutSeconds) {
                if (Test-Path -LiteralPath $expectedFile) {
                    $fileInfo =
                        Get-Item -LiteralPath $expectedFile
                    if ($fileInfo.Length -gt 0) {
                        Write-DiagLog OK `
                            "TSR ZIP successfully created"
                        return [PSCustomObject]@{
                            Success          = $true
                            Manufacturer     = "Dell"
                            Controller       = $manager.Model
                            Firmware         = $manager.FirmwareVersion
                            DiagnosticType   = "TSR"
                            FileType         = "ZIP"
                            ManagementIP     = $ManagementAddress
                            FilePath         = $expectedFile
                            SizeBytes        = $fileInfo.Length
                            Job              = $jobId
                            Method           = "Redfish"
                        }
                    }
                }
                Start-Sleep -Seconds 10
                $elapsed += 10
            }
            throw `
                "Timeout: le TSR Dell n'est pas apparu dans le partage après $timeoutSeconds secondes."
        }
        # ========================================================
        # HPE
        # ========================================================
        elseif ($manufacturer -match "Hewlett|HPE|HP") {
            Write-DiagLog INFO "HPE controller detected"
            # ----------------------------------------------------
            # Découverte Managers/{id}/ActiveHealthSystem
            # ----------------------------------------------------
            $ahsUri = $null
            # On utilise l'URI réelle du manager découverte
            # précédemment.
            $managerId =
                ($managerMember -split "/")[-1]
            $candidateUris = @(
                "$managerMember/ActiveHealthSystem",
                "/redfish/v1/Managers/$managerId/ActiveHealthSystem"
            )
            foreach ($candidate in $candidateUris) {
                try {
                    $ahs =
                        Get-RedfishJson `
                            -Uri "$BaseUri$candidate" `
                            -Credential $ManagementCredential
                    if ($ahs) {
                        $ahsUri = $candidate
                        break
                    }
                }
                catch {
                    continue
                }
            }
            if (-not $ahsUri) {
                throw `
                    "Unsupported: ActiveHealthSystem n'est pas exposé par ce contrôleur HPE via Redfish."
            }
            Write-DiagLog OK `
                "HPE ActiveHealthSystem discovered"
            # ----------------------------------------------------
            # Récupérer la ressource AHS
            # ----------------------------------------------------
            $ahs =
                Get-RedfishJson `
                    -Uri "$BaseUri$ahsUri" `
                    -Credential $ManagementCredential
            # ----------------------------------------------------
            # Chercher les liens AHS documentés
            # ----------------------------------------------------
            $links = $ahs.Links
            $downloadUri = $null
            if ($links) {
                # Parcours récursif des propriétés Links
                foreach ($property in $links.PSObject.Properties) {
                    $value = $property.Value
                    if ($value -is [string]) {
                        if ($value -match "ActiveHealth|AHS") {
                            $downloadUri = $value
                            break
                        }
                    }
                    if ($value.'@odata.id') {
                        $downloadUri = $value.'@odata.id'
                        break
                    }
                }
            }
            if (-not $downloadUri) {
                throw `
                    "ActiveHealthSystem est présent mais aucune URI AHS de téléchargement n'a été découverte."
            }
            if ($downloadUri -notmatch '^https?://') {
                $downloadUri =
                    "$BaseUri$downloadUri"
            }
            # ----------------------------------------------------
            # Nom du fichier
            # ----------------------------------------------------
            $fileName =
                "AHS_{0}_{1}.ahs" -f `
                $ManagementAddress.Replace(".","-"),
                (Get-Date -Format "yyyyMMdd_HHmmss")
            $destinationFile =
                Join-Path `
                    $DestinationShare.TrimEnd("\") `
                    $fileName
            # ----------------------------------------------------
            # URL AHS avec days=N
            # ----------------------------------------------------
            if ($downloadUri -notmatch "\?") {
                $downloadUri += "?days=$AhsDays"
            }
            else {
                $downloadUri += "&days=$AhsDays"
            }
            Write-DiagLog INFO `
                "Downloading HPE AHS ($AhsDays days)"
            # ----------------------------------------------------
            # GET BINAIRE REDFISH
            # ----------------------------------------------------
            Invoke-RedfishRequest `
                -Uri $downloadUri `
                -Method GET `
                -Credential $ManagementCredential `
                -Binary `
                -OutFile $destinationFile | Out-Null
            # ----------------------------------------------------
            # Vérification
            # ----------------------------------------------------
            if (-not (Test-Path -LiteralPath $destinationFile)) {
                throw "Le fichier AHS n'a pas été créé."
            }
            $fileInfo =
                Get-Item -LiteralPath $destinationFile
            if ($fileInfo.Length -le 0) {
                Remove-Item -LiteralPath $destinationFile -Force
                throw "Le fichier AHS téléchargé est vide."
            }
            Write-DiagLog OK `
                "HPE AHS successfully downloaded"
            return [PSCustomObject]@{
                Success          = $true
                Manufacturer     = "HPE"
                Controller       = $manager.Model
                Firmware         = $manager.FirmwareVersion
                DiagnosticType   = "AHS"
                FileType         = "AHS"
                ManagementIP     = $ManagementAddress
                FilePath         = $destinationFile
                SizeBytes        = $fileInfo.Length
                Method           = "Redfish"
            }
        }
        else {
            throw `
                "Unsupported manufacturer via Redfish: $manufacturer"
        }
    }
    catch {
        Write-DiagLog ERROR $_.Exception.Message
        return [PSCustomObject]@{
            Success        = $false
            Manufacturer   = $manufacturer
            ManagementIP   = $ManagementAddress
            DiagnosticType = $null
            FilePath       = $null
            Method         = "Redfish"
            Error          = $_.Exception.Message
        }
    }
    finally {
        if ($SkipCertificateCheck -and
            $PSVersionTable.PSVersion.Major -lt 7) {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback =
                $oldCallback
        }
    }
}

Exemple Dell

$idracCredential = Get-Credential
$shareCredential = Get-Credential
$result = Get-HardwareDiagnostic `
    -ManagementAddress "10.10.10.50" `
    -ManagementCredential $idracCredential `
    -ShareCredential $shareCredential `
    -DestinationShare "\\BMAAS-SRV\Diagnostics" `
    -SkipCertificateCheck
$result

Pour Dell, le résultat attendu est :

Success        : True
Manufacturer   : Dell
DiagnosticType : TSR
FileType       : ZIP
FilePath       : \\BMAAS-SRV\Diagnostics\TSR_10-10-10-50_20261008_100000.zip
Method         : Redfish

Important : le ShareCredential doit avoir le droit d’écrire dans le partage. L’iDRAC utilise ces identifiants pour déposer le ZIP. Dell documente CIFS comme ShareType et ShareName, UserName, Password, IPAddress et FileName comme paramètres de l’action. 

Exemple HPE

$iloCredential = Get-Credential
$result = Get-HardwareDiagnostic `
    -ManagementAddress "10.10.10.60" `
    -ManagementCredential $iloCredential `
    -DestinationShare "\\BMAAS-SRV\Diagnostics" `
    -AhsDays 30 `
    -SkipCertificateCheck
$result

Ici, contrairement à Dell, PowerShell télécharge le fichier AHS par Redfish, puis l’écrit directement dans le partage. C’est conforme au workflow HPE documenté : découverte de HpeiLOActiveHealthSystem, récupération de l’URI AHS et GET binaire avec days, from/to ou downloadAll. 

⚠️ Une limite volontaire sur iDRAC 7/8

Je veux être très clair là-dessus parce que c’est précisément ce que tu m’as demandé : je n’ai pas ajouté un faux endpoint pour iDRAC7/8.

Dell documente officiellement ExportTechSupportReport sur les guides Redfish iDRAC9. Pour iDRAC7/8, la documentation Dell actuelle renvoie à leur procédure d’export TSR/SupportAssist via leurs interfaces/CLI, et je n’ai pas trouvé de documentation constructeur établissant un endpoint Redfish équivalent permettant de générer le ZIP. 

Donc avec ton exigence « 100 % Redfish », le comportement correct est :

iDRAC9/10 compatible
        ↓
Redfish
        ↓
TSR.zip
        ↓
Share

mais :

iDRAC7/8
        ↓
Redfish
        ↓
capacité TSR non documentée/exposée
        ↓
UNSUPPORTED

Pas de RACADM en douce.

C’est important aussi parce que Dell a encore modifié les mécanismes SupportAssist/TSR entre générations et firmwares. 

Enfin, pour ton usage BMAAS, je te conseille de garder cette séparation : Dell → iDRAC écrit le ZIP directement dans le share ; HPE → PowerShell télécharge l’AHS puis le copie dans le share. C’est beaucoup plus fidèle aux API Redfish réellement documentées que d’essayer de forcer Dell et HPE dans exactement le même workflow.
