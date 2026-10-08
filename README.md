https://www.powershellgallery.com/packages/Invoke-SupportAssistCollectionLocalREDFISH/9.0.0/Content/Invoke-SupportAssistCollectionLocalREDFISH.psm1
https://www.powershellgallery.com/packages/Invoke-SupportAssistCollectionLocalREDFISH/9.0.0

https://redfish.redoc.ly/docs/redfishservices/ilos/supplementdocuments/logservices/?utm_source

Oui. Cette fois je te donne une version basée sur des implémentations constructeur réelles, pas sur des endpoints imaginés.

J’ai vérifié notamment le cmdlet officiel Dell Invoke-SupportAssistCollectionLocalREDFISH : Dell utilise bien l’action DellLCService.SupportAssistCollection, avec ShareType = Local, puis surveille le job et récupère le ZIP localement. La version actuelle 9.0.0 est publiée par Dell et indique explicitement que la collection locale se fait en Redfish. 

Côté HPE, la documentation officielle décrit exactement le mécanisme AHS : découverte de HpeiLOActiveHealthSystem, récupération de Links.AHSLocation.extref, puis GET du fichier binaire .ahs avec downloadAll=1 ou days=N. 

Ce que cette fonction fait

* 100 % Redfish
* Dell : SupportAssist / TSR local → ZIP téléchargé sur le PC qui exécute PowerShell
* HPE : AHS → .ahs téléchargé sur le PC
* Aucun RACADM
* Aucun iLOREST
* Aucun ShareName
* Aucun ShareCredential
* Aucun export CIFS/NFS
* Détection constructeur par /redfish/v1
* Détection de la capacité Dell par l’action réellement exposée par l’iDRAC, pas simplement par une version supposée
* Pour HPE, découverte du lien AHS réellement exposé par l’iLO
* Polling automatique du job Dell
* Support du schéma Dell iDRAC9 et iDRAC10 en fonction de la Location réellement retournée
* Si le contrôleur ne supporte pas la fonction : Unsupported, pas de fallback bidon.

function Get-HardwareDiagnostic {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManagementAddress,
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory = $false)]
        [string]$OutputDirectory = ".\HardwareDiagnostics",
        # Pour HPE :
        # $null = téléchargement complet de l'AHS
        # 7     = uniquement les 7 derniers jours
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 3650)]
        [int]$AhsDays,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 120)]
        [int]$PollIntervalSeconds = 10,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 180)]
        [int]$TimeoutMinutes = 60,
        # À utiliser si le certificat HTTPS du BMC est auto-signé
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck
    )
    Set-StrictMode -Version Latest
    $ErrorActionPreference = "Stop"
    # ------------------------------------------------------------
    # Normalisation adresse
    # ------------------------------------------------------------
    $ManagementAddress = $ManagementAddress.Trim()
    $ManagementAddress = $ManagementAddress `
        -replace '^https://', '' `
        -replace '^http://', '' `
        -replace '/+$', ''
    $BaseUri = "https://$ManagementAddress"
    # ------------------------------------------------------------
    # Création répertoire local
    # ------------------------------------------------------------
    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }
    $OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
    # ------------------------------------------------------------
    # Ignore certificat uniquement si demandé
    #
    # Compatible PowerShell 5.1.
    # ------------------------------------------------------------
    if ($SkipCertificateCheck) {
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            # PowerShell 7 :
            # -SkipCertificateCheck sera ajouté directement aux requêtes.
        }
        else {
            # PowerShell 5.1 :
            # ancienne méthode .NET nécessaire.
            try {
                if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
                    Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy
{
    public bool CheckValidationResult(
        ServicePoint srvPoint,
        X509Certificate certificate,
        WebRequest request,
        int certificateProblem)
    {
        return true;
    }
}
"@
                }
                [System.Net.ServicePointManager]::CertificatePolicy =
                    New-Object TrustAllCertsPolicy
            }
            catch {
                Write-Verbose "Le bypass SSL PowerShell 5.1 n'a pas pu être installé : $($_.Exception.Message)"
            }
        }
    }
    # ------------------------------------------------------------
    # Helper : construction des paramètres Invoke-WebRequest
    # ------------------------------------------------------------
    function New-RequestParameters {
        param(
            [string]$Uri,
            [ValidateSet("GET", "POST", "PATCH")]
            [string]$Method = "GET",
            [string]$Body,
            [string]$OutFile
        )
        $params = @{
            Uri         = $Uri
            Method      = $Method
            Credential  = $Credential
            UseBasicParsing = $true
            ErrorAction = "Stop"
            Headers     = @{
                "Accept" = "application/json"
            }
        }
        if ($Body) {
            $params["Body"] = $Body
            $params["ContentType"] = "application/json"
        }
        if ($OutFile) {
            $params["OutFile"] = $OutFile
        }
        if ($PSVersionTable.PSVersion.Major -ge 7 -and $SkipCertificateCheck) {
            $params["SkipCertificateCheck"] = $true
        }
        return $params
    }
    # ------------------------------------------------------------
    # Helper : requête GET JSON
    # ------------------------------------------------------------
    function Invoke-RedfishJsonGet {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Uri
        )
        $params = New-RequestParameters -Uri $Uri -Method "GET"
        $response = Invoke-WebRequest @params
        if ($response.StatusCode -lt 200 -or $response.StatusCode -ge 300) {
            throw "GET Redfish échoué : HTTP $($response.StatusCode) - $Uri"
        }
        if ([string]::IsNullOrWhiteSpace($response.Content)) {
            return $null
        }
        return ($response.Content | ConvertFrom-Json)
    }
    # ------------------------------------------------------------
    # Helper : requête POST JSON
    # ------------------------------------------------------------
    function Invoke-RedfishJsonPost {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Uri,
            [Parameter(Mandatory = $true)]
            [string]$Body
        )
        $params = New-RequestParameters `
            -Uri $Uri `
            -Method "POST" `
            -Body $Body
        return Invoke-WebRequest @params
    }
    # ------------------------------------------------------------
    # Helper : URL relative -> URL absolue
    # ------------------------------------------------------------
    function ConvertTo-AbsoluteRedfishUri {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Uri
        )
        if ($Uri -match '^https?://') {
            return $Uri
        }
        if ($Uri.StartsWith("/")) {
            return "$BaseUri$Uri"
        }
        return "$BaseUri/$Uri"
    }
    # ------------------------------------------------------------
    # Helper : récupération d'un header HTTP
    # Compatible PowerShell 5.1 / 7
    # ------------------------------------------------------------
    function Get-ResponseHeader {
        param(
            [Parameter(Mandatory = $true)]
            $Response,
            [Parameter(Mandatory = $true)]
            [string]$Name
        )
        try {
            $value = $Response.Headers[$Name]
            if ($value) {
                return [string]$value
            }
        }
        catch {
        }
        return $null
    }
    # ------------------------------------------------------------
    # Helper : nom de fichier sécurisé
    # ------------------------------------------------------------
    function ConvertTo-SafeFileName {
        param(
            [string]$Name
        )
        if ([string]::IsNullOrWhiteSpace($Name)) {
            return "diagnostic"
        }
        foreach ($char in [System.IO.Path]::GetInvalidFileNameChars()) {
            $Name = $Name.Replace($char, "_")
        }
        return $Name
    }
    # ------------------------------------------------------------
    # 1. Découverte Redfish
    # ------------------------------------------------------------
    try {
        Write-Verbose "Connexion Redfish : $BaseUri/redfish/v1"
        $root = Invoke-RedfishJsonGet `
            -Uri "$BaseUri/redfish/v1"
    }
    catch {
        return [PSCustomObject]@{
            Success         = $false
            Status          = "ConnectionFailed"
            Manufacturer    = $null
            Controller      = $null
            Firmware        = $null
            DiagnosticType  = $null
            FilePath        = $null
            SizeBytes       = $null
            Method          = "Redfish"
            Error           = $_.Exception.Message
        }
    }
    # ------------------------------------------------------------
    # 2. Détermination constructeur
    #
    # On regarde les Managers exposés par Redfish.
    # ------------------------------------------------------------
    $manufacturer = $null
    $controller = $null
    $firmware = $null
    $managerUri = $null
    $manager = $null
    try {
        if (-not $root.Managers.'@odata.id') {
            throw "La ressource Redfish Managers n'est pas exposée."
        }
        $managersCollection = Invoke-RedfishJsonGet `
            -Uri (ConvertTo-AbsoluteRedfishUri $root.Managers.'@odata.id')
        if (-not $managersCollection.Members) {
            throw "Aucun Manager Redfish n'a été trouvé."
        }
        foreach ($member in $managersCollection.Members) {
            if (-not $member.'@odata.id') {
                continue
            }
            try {
                $candidate = Invoke-RedfishJsonGet `
                    -Uri (ConvertTo-AbsoluteRedfishUri $member.'@odata.id')
            }
            catch {
                continue
            }
            if ($candidate.Manufacturer) {
                $manufacturer = [string]$candidate.Manufacturer
            }
            if ($candidate.Model) {
                $controller = [string]$candidate.Model
            }
            if ($candidate.FirmwareVersion) {
                $firmware = [string]$candidate.FirmwareVersion
            }
            if (
                $candidate.Manufacturer -match "Dell|Hewlett|HPE" -or
                $candidate.Model -match "iDRAC|iLO"
            ) {
                $managerUri = [string]$member.'@odata.id'
                $manager = $candidate
                break
            }
        }
    }
    catch {
        return [PSCustomObject]@{
            Success         = $false
            Status          = "ManagerDiscoveryFailed"
            Manufacturer    = $manufacturer
            Controller      = $controller
            Firmware        = $firmware
            DiagnosticType  = $null
            FilePath        = $null
            SizeBytes       = $null
            Method          = "Redfish"
            Error           = $_.Exception.Message
        }
    }
    if (-not $managerUri) {
        return [PSCustomObject]@{
            Success         = $false
            Status          = "Unsupported"
            Manufacturer    = $manufacturer
            Controller      = $controller
            Firmware        = $firmware
            DiagnosticType  = $null
            FilePath        = $null
            SizeBytes       = $null
            Method          = "Redfish"
            Error           = "Impossible d'identifier un iDRAC ou un iLO via Redfish."
        }
    }
    # ============================================================
    # DELL iDRAC
    # ============================================================
    if ($manufacturer -match "Dell" -or $controller -match "iDRAC") {
        Write-Host ""
        Write-Host "=== DELL iDRAC ===" -ForegroundColor Cyan
        Write-Host "Controller : $controller"
        Write-Host "Firmware   : $firmware"
        # --------------------------------------------------------
        # Vérification réelle de l'action SupportAssistCollection
        #
        # C'est exactement le mécanisme utilisé par Dell dans son
        # cmdlet officiel Invoke-SupportAssistCollectionLocalREDFISH.
        # --------------------------------------------------------
        $lcServiceUri =
            "$managerUri/Oem/Dell/DellLCService"
        try {
            $lcService = Invoke-RedfishJsonGet `
                -Uri (ConvertTo-AbsoluteRedfishUri $lcServiceUri)
        }
        catch {
            return [PSCustomObject]@{
                Success         = $false
                Status          = "Unsupported"
                Manufacturer    = $manufacturer
                Controller      = $controller
                Firmware        = $firmware
                DiagnosticType  = "Dell SupportAssist"
                FilePath        = $null
                SizeBytes       = $null
                Method          = "Redfish OEM"
                Error           = "DellLCService inaccessible : $($_.Exception.Message)"
            }
        }
        $supportAssistAction = $null
        if ($lcService.Actions) {
            $supportAssistAction =
                $lcService.Actions.PSObject.Properties |
                Where-Object {
                    $_.Name -eq "#DellLCService.SupportAssistCollection"
                } |
                Select-Object -First 1
        }
        if (-not $supportAssistAction) {
            return [PSCustomObject]@{
                Success         = $false
                Status          = "Unsupported"
                Manufacturer    = $manufacturer
                Controller      = $controller
                Firmware        = $firmware
                DiagnosticType  = "Dell SupportAssist"
                FilePath        = $null
                SizeBytes       = $null
                Method          = "Redfish OEM"
                Error           = "L'action DellLCService.SupportAssistCollection n'est pas exposée par cet iDRAC."
            }
        }
        # --------------------------------------------------------
        # Sélection des données
        #
        # HWData     = données hardware
        # DebugLogs  = logs de debug
        # OSAppData  = données OS/applications
        # TTYLogs    = TTY logs
        #
        # On prend le maximum pertinent pour un diagnostic.
        # --------------------------------------------------------
        $dataSelectors = @(
            "DebugLogs",
            "HWData",
            "OSAppData",
            "TTYLogs"
        )
        $bodyObject = [ordered]@{
            ShareType          = "Local"
            DataSelectorArrayIn = $dataSelectors
        }
        $body = $bodyObject | ConvertTo-Json -Depth 5 -Compress
        $actionTarget = $null
        # L'objet Action Redfish contient normalement Target.
        if ($supportAssistAction.Value.Target) {
            $actionTarget = [string]$supportAssistAction.Value.Target
        }
        # Sécurité : si Target n'est pas fourni, on utilise
        # l'URI exacte utilisée par Dell dans son cmdlet officiel.
        if ([string]::IsNullOrWhiteSpace($actionTarget)) {
            $actionTarget =
                "$lcServiceUri/Actions/DellLCService.SupportAssistCollection"
        }
        $actionTarget = ConvertTo-AbsoluteRedfishUri $actionTarget
        Write-Host "Action      : DellLCService.SupportAssistCollection"
        Write-Host "Mode        : Local"
        Write-Host "Téléchargement : machine PowerShell"
        # --------------------------------------------------------
        # Lancement collection
        # --------------------------------------------------------
        try {
            $postResponse = Invoke-RedfishJsonPost `
                -Uri $actionTarget `
                -Body $body
        }
        catch {
            return [PSCustomObject]@{
                Success         = $false
                Status          = "CollectionStartFailed"
                Manufacturer    = $manufacturer
                Controller      = $controller
                Firmware        = $firmware
                DiagnosticType  = "Dell SupportAssist"
                FilePath        = $null
                SizeBytes       = $null
                Method          = "Redfish OEM"
                Error           = $_.Exception.Message
            }
        }
        if ($postResponse.StatusCode -ne 200 -and
            $postResponse.StatusCode -ne 202) {
            return [PSCustomObject]@{
                Success         = $false
                Status          = "CollectionStartFailed"
                Manufacturer    = $manufacturer
                Controller      = $controller
                Firmware        = $firmware
                DiagnosticType  = "Dell SupportAssist"
                FilePath        = $null
                SizeBytes       = $null
                Method          = "Redfish OEM"
                Error           = "Lancement SupportAssist refusé : HTTP $($postResponse.StatusCode)"
            }
        }
        # --------------------------------------------------------
        # Dell retourne une Location contenant le job.
        #
        # iDRAC9 :
        #   /redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/Jobs/...
        #
        # iDRAC10 :
        #   /redfish/v1/TaskService/TaskMonitors/...
        #
        # On ne devine pas la génération : on utilise la Location
        # réellement renvoyée par le contrôleur.
        # --------------------------------------------------------
        $jobLocation = Get-ResponseHeader `
            -Response $postResponse `
            -Name "Location"
        if ([string]::IsNullOrWhiteSpace($jobLocation)) {
            return [PSCustomObject]@{
                Success         = $false
                Status          = "NoJobLocation"
                Manufacturer    = $manufacturer
                Controller      = $controller
                Firmware        = $firmware
                DiagnosticType  = "Dell SupportAssist"
                FilePath        = $null
                SizeBytes       = $null
                Method          = "Redfish OEM"
                Error           = "Le POST SupportAssist n'a pas retourné de header Location."
            }
        }
        $jobUri = ConvertTo-AbsoluteRedfishUri $jobLocation
        Write-Host "Job         : $jobUri"
        Write-Host "Attente de génération du fichier..."
        # --------------------------------------------------------
        # Polling
        # --------------------------------------------------------
        $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
        $downloadUri = $null
        $lastMessage = $null
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds $PollIntervalSeconds
            try {
                $jobResponse = Invoke-WebRequest @(
                    New-RequestParameters `
                        -Uri $jobUri `
                        -Method "GET"
                )
            }
            catch {
                $lastMessage = $_.Exception.Message
                Write-Verbose "Polling Dell : $lastMessage"
                continue
            }
            $jobStatusCode = [int]$jobResponse.StatusCode
            $jobJson = $null
            if (-not [string]::IsNullOrWhiteSpace($jobResponse.Content)) {
                try {
                    $jobJson = $jobResponse.Content | ConvertFrom-Json
                }
                catch {
                    $jobJson = $null
                }
            }
            # ----------------------------------------------------
            # iDRAC10 :
            # TaskMonitor termine avec HTTP 204 et Location
            # vers le fichier TSR.
            # ----------------------------------------------------
            if ($jobStatusCode -eq 204) {
                $downloadLocation = Get-ResponseHeader `
                    -Response $jobResponse `
                    -Name "Location"
                if ($downloadLocation) {
                    $downloadUri =
                        ConvertTo-AbsoluteRedfishUri $downloadLocation
                }
                break
            }
            # ----------------------------------------------------
            # iDRAC9 :
            # Le job expose le message de progression et Location
            # du fichier lorsqu'il est terminé.
            # ----------------------------------------------------
            if ($jobJson) {
                $lastMessage = $null
                if ($jobJson.Message) {
                    $lastMessage = [string]$jobJson.Message
                }
                $failed =
                    $false
                if ($lastMessage) {
                    if ($lastMessage -match "Fail|Failed|failed|already") {
                        $failed = $true
                    }
                }
                if ($failed) {
                    return [PSCustomObject]@{
                        Success         = $false
                        Status          = "CollectionFailed"
                        Manufacturer    = $manufacturer
                        Controller      = $controller
                        Firmware        = $firmware
                        DiagnosticType  = "Dell SupportAssist"
                        FilePath        = $null
                        SizeBytes       = $null
                        Method          = "Redfish OEM"
                        Error           = "SupportAssist a échoué : $lastMessage"
                    }
                }
                if ($lastMessage -match "complete|completed successfully") {
                    $downloadLocation = Get-ResponseHeader `
                        -Response $jobResponse `
                        -Name "Location"
                    if ($downloadLocation) {
                        $downloadUri =
                            ConvertTo-AbsoluteRedfishUri $downloadLocation
                    }
                    else {
                        # Dell documente également cette URI de
                        # téléchargement pour le workflow iDRAC9.
                        $downloadUri =
                            "$BaseUri/redfish/v1/Dell/sacollect.zip"
                    }
                    break
                }
            }
            Write-Host "." -NoNewline
        }
        Write-Host ""
        if ([string]::IsNullOrWhiteSpace($downloadUri)) {
            return [PSCustomObject]@{
                Success         = $false
                Status          = "Timeout"
                Manufacturer    = $manufacturer
                Controller      = $controller
                Firmware        = $firmware
                DiagnosticType  = "Dell SupportAssist"
                FilePath        = $null
                SizeBytes       = $null
                Method          = "Redfish OEM"
                Error           = "La collecte n'est pas terminée après $TimeoutMinutes minutes. Dernier message : $lastMessage"
            }
        }
        # --------------------------------------------------------
        # Téléchargement local du ZIP
        # --------------------------------------------------------
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $safeController =
            ConvertTo-SafeFileName $controller
        $fileName =
            "Dell_${safeController}_SupportAssist_${timestamp}.zip"
        $localPath =
            Join-Path $OutputDirectory $fileName
        Write-Host "Téléchargement local : $localPath"
        try {
            $downloadParams = New-RequestParameters `
                -Uri $downloadUri `
                -Method "GET" `
                -OutFile $localPath
            # Pour un fichier binaire, on retire Accept JSON.
            $downloadParams["Headers"] = @{
                "Accept" = "application/zip, application/octet-stream, */*"
            }
            Invoke-WebRequest @downloadParams | Out-Null
        }
        catch {
            return [PSCustomObject]@{
                Success         = $false
                Status          = "DownloadFailed"
                Manufacturer    = $manufacturer
                Controller      = $controller
                Firmware        = $firmware
                DiagnosticType  = "Dell SupportAssist"
                FilePath        = $null
                SizeBytes       = $null
                Method          = "Redfish OEM"
                Error           = "Téléchargement du ZIP impossible : $($_.Exception.Message)"
            }
        }
        if (-not (Test-Path -LiteralPath $localPath)) {
            return [PSCustomObject]@{
                Success         = $false
                Status          = "DownloadFailed"
                Manufacturer    = $manufacturer
                Controller      = $controller
                Firmware        = $firmware
                DiagnosticType  = "Dell SupportAssist"
                FilePath        = $null
                SizeBytes       = $null
                Method          = "Redfish OEM"
                Error           = "Le fichier ZIP n'a pas été créé localement."
            }
        }
        $fileInfo = Get-Item -LiteralPath $localPath
        return [PSCustomObject]@{
            Success         = $true
            Status          = "Completed"
            Manufacturer    = $manufacturer
            Controller      = $controller
            Firmware        = $firmware
            DiagnosticType  = "Dell SupportAssist / TSR"
            FilePath        = $fileInfo.FullName
            SizeBytes       = $fileInfo.Length
            Method          = "Redfish OEM - SupportAssistCollection"
            Error           = $null
        }
    }
    # ============================================================
    # HPE iLO
    # ============================================================
    if ($manufacturer -match "HPE|Hewlett" -or $controller -match "iLO") {
        Write-Host ""
        Write-Host "=== HPE iLO ===" -ForegroundColor Cyan
        Write-Host "Controller : $controller"
        Write-Host "Firmware   : $firmware"
        # --------------------------------------------------------
        # Découverte du lien ActiveHealthSystem.
        #
        # HPE documente :
        # Oem/Hpe/Links/ActiveHealthSystem
        # --------------------------------------------------------
        $ahsUri = $null
        if ($manager.Oem -and
            $manager.Oem.Hpe -and
            $manager.Oem.Hpe.Links -and
            $manager.Oem.Hpe.Links.ActiveHealthSystem) {
            $ahsLink =
                $manager.Oem.Hpe.Links.ActiveHealthSystem
            if ($ahsLink.'@odata.id') {
                $ahsUri = [string]$ahsLink.'@odata.id'
            }
            elseif ($ahsLink.'href') {
                $ahsUri = [string]$ahsLink.href
            }
            elseif ($ahsLink.'extref') {
                $ahsUri = [string]$ahsLink.extref
            }
        }
        # Certains firmware exposent directement la ressource sous
        # le Manager. On ne suppose pas l'ID "1" : on utilise le
        # manager découvert précédemment.
        if (-not $ahsUri) {
            $candidateAhsUri =
                "$managerUri/ActiveHealthSystem"
            try {
                $testAhs = Invoke-RedfishJsonGet `
                    -Uri (ConvertTo-AbsoluteRedfishUri $candidateAhsUri)
                if ($testAhs.'@odata.type' -match "HpeiLOActiveHealthSystem") {
                    $ahsUri = $candidateAhsUri
                }
            }
            catch {
                # On laisse le message Unsupported plus bas.
            }
        }
        if (-not $ahsUri) {
            return [PSCustomObject]@{
                Success         = $false
                Status          = "Unsupported"
                Manufacturer    = $manufacturer
                Controller      = $controller
                Firmware        = $firmware
                DiagnosticType  = "HPE Active Health System"
                FilePath        = $null
                SizeBytes       = $null
                Method          = "Redfish OEM"
                Error           = "La ressource HpeiLOActiveHealthSystem n'est pas exposée par cet iLO."
            }
        }
        $ahsUri = ConvertTo-AbsoluteRedfishUri $ahsUri
        Write-Host "AHS resource : $ahsUri"
        # --------------------------------------------------------
        # GET ActiveHealthSystem
        # --------------------------------------------------------
        try {
            $ahsResource = Invoke-RedfishJsonGet -Uri $ahsUri
        }
        catch {
            return [PSCustomObject]@{
                Success         = $false
                Status          = "AhsDiscoveryFailed"
                Manufacturer    = $manufacturer
                Controller      = $controller
                Firmware        = $firmware
                DiagnosticType  = "HPE Active Health System"
                FilePath        = $null
                SizeBytes       = $null
                Method          = "Redfish OEM"
                Error           = $_.Exception.Message
            }
        }
        # --------------------------------------------------------
        # HPE documente Links.AHSLocation.extref
        # --------------------------------------------------------
        $ahsDownloadUri = $null
        if ($ahsResource.Links -and
            $ahsResource.Links.AHSLocation) {
            if ($ahsResource.Links.AHSLocation.extref) {
                $ahsDownloadUri =
                    [string]$ahsResource.Links.AHSLocation.extref
            }
        }
        if (-not $ahsDownloadUri) {
            return [PSCustomObject]@{
                Success         = $false
                Status          = "AhsLocationUnavailable"
                Manufacturer    = $manufacturer
                Controller      = $controller
                Firmware        = $firmware
                DiagnosticType  = "HPE Active Health System"
                FilePath        = $null
                SizeBytes       = $null
                Method          = "Redfish OEM"
                Error           = "Links.AHSLocation.extref n'est pas disponible dans la ressource AHS."
            }
        }
        # --------------------------------------------------------
        # Si days est spécifié :
        #
        # /ahsdata/...ahs?days=7
        #
        # Sinon :
        #
        # /ahsdata/...ahs?downloadAll=1
        # --------------------------------------------------------
        if ($AhsDays) {
            # On retire éventuellement les paramètres déjà présents.
            $ahsDownloadUri = $ahsDownloadUri -replace '\?.*$', ''
            $ahsDownloadUri =
                "$ahsDownloadUri?days=$AhsDays"
        }
        else {
            # L'URL officielle peut déjà contenir downloadAll=1.
            # Si elle ne l'a pas, on l'ajoute.
            if ($ahsDownloadUri -notmatch 'downloadAll=') {
                if ($ahsDownloadUri.Contains("?")) {
                    $ahsDownloadUri += "&downloadAll=1"
                }
                else {
                    $ahsDownloadUri += "?downloadAll=1"
                }
            }
        }
        $ahsDownloadUri =
            ConvertTo-AbsoluteRedfishUri $ahsDownloadUri
        Write-Host "AHS download : $ahsDownloadUri"
        # --------------------------------------------------------
        # Nom local
        # --------------------------------------------------------
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $safeController =
            ConvertTo-SafeFileName $controller
        $fileName =
            "HPE_${safeController}_AHS_${timestamp}.ahs"
        $localPath =
            Join-Path $OutputDirectory $fileName
        Write-Host "Téléchargement local : $localPath"
        # --------------------------------------------------------
        # GET binaire AHS
        # --------------------------------------------------------
        try {
            $downloadParams = New-RequestParameters `
                -Uri $ahsDownloadUri `
                -Method "GET" `
                -OutFile $localPath
            $downloadParams["Headers"] = @{
                "Accept" = "application/octet-stream, application/octet-stream"
            }
            Invoke-WebRequest @downloadParams | Out-Null
        }
        catch {
            return [PSCustomObject]@{
                Success         = $false
                Status          = "DownloadFailed"
                Manufacturer    = $manufacturer
                Controller      = $controller
                Firmware        = $firmware
                DiagnosticType  = "HPE Active Health System"
                FilePath        = $null
                SizeBytes       = $null
                Method          = "Redfish OEM - ActiveHealthSystem"
                Error           = "Téléchargement AHS impossible : $($_.Exception.Message)"
            }
        }
        if (-not (Test-Path -LiteralPath $localPath)) {
            return [PSCustomObject]@{
                Success         = $false
                Status          = "DownloadFailed"
                Manufacturer    = $manufacturer
                Controller      = $controller
                Firmware        = $firmware
                DiagnosticType  = "HPE Active Health System"
                FilePath        = $null
                SizeBytes       = $null
                Method          = "Redfish OEM - ActiveHealthSystem"
                Error           = "Le fichier AHS n'a pas été créé localement."
            }
        }
        $fileInfo = Get-Item -LiteralPath $localPath
        return [PSCustomObject]@{
            Success         = $true
            Status          = "Completed"
            Manufacturer    = $manufacturer
            Controller      = $controller
            Firmware        = $firmware
            DiagnosticType  = "HPE Active Health System"
            FilePath        = $fileInfo.FullName
            SizeBytes       = $fileInfo.Length
            Method          = "Redfish OEM - HpeiLOActiveHealthSystem"
            Error           = $null
        }
    }
    # ============================================================
    # Constructeur non supporté
    # ============================================================
    return [PSCustomObject]@{
        Success         = $false
        Status          = "Unsupported"
        Manufacturer    = $manufacturer
        Controller      = $controller
        Firmware        = $firmware
        DiagnosticType  = $null
        FilePath        = $null
        SizeBytes       = $null
        Method          = "Redfish"
        Error           = "Constructeur de BMC non supporté par cette fonction."
    }
}

Utilisation Dell

Par exemple :

$cred = Get-Credential
$result = Get-HardwareDiagnostic `
    -ManagementAddress "10.10.10.50" `
    -Credential $cred `
    -OutputDirectory "C:\BMAAS\Diagnostics" `
    -SkipCertificateCheck
$result | Format-List

Tu obtiendras quelque chose du genre :

Success        : True
Status         : Completed
Manufacturer   : Dell Inc.
Controller     : iDRAC9
Firmware       : 7.x.x.x
DiagnosticType : Dell SupportAssist / TSR
FilePath       : C:\BMAAS\Diagnostics\Dell_iDRAC9_SupportAssist_20261008_193000.zip
SizeBytes      : 18456321
Method         : Redfish OEM - SupportAssistCollection
Error          :

Point important : le ZIP est téléchargé par Invoke-WebRequest vers C:\BMAAS\Diagnostics. Il n’est jamais demandé à l’iDRAC de déposer le fichier sur un partage réseau.

Dell confirme dans son propre module que le lancement se fait avec :

ShareType = Local
DataSelectorArrayIn = DebugLogs / HWData / OSAppData / TTYLogs

puis sur iDRAC9 le job est interrogé sous .../Oem/Dell/Jobs/..., tandis que pour iDRAC10 le module Dell utilise .../TaskService/TaskMonitors/.... 

Utilisation HPE

Pour télécharger tout l’AHS :

$cred = Get-Credential
$result = Get-HardwareDiagnostic `
    -ManagementAddress "10.10.10.60" `
    -Credential $cred `
    -OutputDirectory "C:\BMAAS\Diagnostics" `
    -SkipCertificateCheck
$result | Format-List

Pour seulement les 7 derniers jours :

$result = Get-HardwareDiagnostic `
    -ManagementAddress "10.10.10.60" `
    -Credential $cred `
    -OutputDirectory "C:\BMAAS\Diagnostics" `
    -AhsDays 7 `
    -SkipCertificateCheck

HPE documente bien days=N pour limiter la période et downloadAll=1 pour télécharger l’intégralité de l’AHS. Le fichier retourné est un téléchargement binaire HTTP 200 que le client peut sauvegarder localement. 

Et surtout : ce que je ne prétends PAS

Je ne vais pas te dire :

« iDRAC 7 = forcément supporté, iDRAC 8 = forcément supporté, iDRAC 9 = forcément supporté… »

juste parce que le numéro de version existe.

La fonction teste réellement la capacité Redfish exposée par le BMC. Pour Dell, elle vérifie que #DellLCService.SupportAssistCollection existe avant de lancer quoi que ce soit. C’est également la logique employée par le script Dell officiel. 

Donc si tu lui donnes un ancien iDRAC qui ne publie pas cette action, tu obtiens :

Status : Unsupported

et pas un faux succès, pas de RACADM caché, pas de fallback.

Pour HPE, même logique : on cherche réellement HpeiLOActiveHealthSystem, puis Links.AHSLocation.extref. HPE indique que l’URI AHS n’est justement pas à inventer : elle doit être lue depuis cette propriété. 

C’est cette approche que je te conseille pour BMAAS : capability-based plutôt que version-based. Elle sera beaucoup plus propre quand tu vas rencontrer différents modèles Dell/HPE et différentes versions de firmware.

lien 
https://hewlettpackard.github.io/ilo-rest-api-docs/ilo4/?utm_source=chatgpt.com#redfish-1-0-conformance
