#  Observations on ARM (Bicep) Templates # 

## - Azure Deployment Framework ## 
Go Home [Documentation Home](./index.md)

### Getting Started - Deploy your First App
- [Documentation - Getting Started - Deploy your Second App](./Getting_Started2.md)

#### *Azure Resource Group Deployment - Multi-Region/Multi-Tier Hub/Spoke Environments*

#### This project assumes:
- Shared Subscription between all Apps/Tenants
- Shared Hub between all Apps/Tenants
- Shared Global resource Group between all Apps/Tenants

### Why Shared? Because this project should be managed by a single SRE/DevOps team.
<br/>

### Pre requisites

1. You have a subscription to deploy into, preferrably a blank subscription, this is a Greenfields project, not Brownfields
1. You are an owner on the Subscription
1. You know your /20 Network Range that you can deploy into, you need 2 of these
    1. One range in the Primary (Azure Partner) Region
    1. One range in the Secondary (Azure Partner) Region

## Steps

1. There are several setup/management scripts in this directory: ADF\1-PrereqsToDeploy\CustomResources
1. There are several shared metadata files in your Tenant Directory e.g. Global-Global, AZC1-Global, AZE2-Global
1. We will start with the HUB Tenant, this is the Shared Hub
1. We will also deploy the HUB Global Resource, this is shared Global resources
1. Open the following File and fill out all of the information ADF\tenants\HUB\Global-Global.json
    1. All of the info below should be filled out ahead of time
    1. Replace the 3 Characters that map to the Name of your App, in this case HUB, you can leave HUB
        ````
        "Global": {
            "tenantId": "3254f91d-4657-40df-962d-c8e6dad75963",               // Your Azure AD TenantID
            "SubscriptionID": "1f0713fe-9b12-4c8f-ab0c-26aba7aaa3e5",        // The Subscription ID where your Resource Groups will be deployed
            "hubSubscriptionID": "1f0713fe-9b12-4c8f-ab0c-26aba7aaa3e5",     // The Subscription ID where your Hub VNET will be deployed
            "OrgName": "BRW",                       // "3-Letter-Company-Name"  e.g. This is required to ensure all public resources deployed have a unique name
                                                        // This should stay the same across ALL Tenants, only the AppName will change
                                                        // Be sure to keep this consistent
            "AppName": "HUB",                       // "3-Letter-App-Name" e.g. in this project, we call this the tenant name.
            "SAName": "azc1brwhubg1saglobal",       // "{Primary-Azure-Region-azxx-lower-case}{orgname-3-char-max-lower-case}{appname-3-char-max-lower-case}g1saglobal" 
                                                        // max length of storage account is 24 chars and requires lowercase
            "GlobalRGName": "AZC1-BRW-HUB-RG-G1",       // "{Primary-Azure-Region-AZXX}-{appname-3-characters-max-upper-case}-RG-G1"  G1 is Global
            "PrimaryLocation": "CentralUS",         // "CentralUS" e.g. partner region to East US 2
            "PrimaryPrefix": "AZC1",                // "AZ{2-character-letters-for-the-Azure-Region}" e.g. C1 Central US 1, E2 East US 2 Etc
            "SecondaryLocation": "EastUS2",         // "EastUS2" e.g. partner region to Central US
            "SecondaryPrefix": "AZE2",              // "AZ{2-character-letters-for-the-Azure-Region}" e.g. C1 Central US 1, E2 East US 2 Etc
            "PublicIPAddressforRemoteAccess": "73.157.100.227/32",      // This IP will be used on NSG's if you have a Public IP
            "vmAdminUserName": "brw",               // "Local-Admin-UserName-for-Virtual-Machines"
            "DomainName": "psthing.com",            // "Interntal Active Directory Domain"
            "DomainNameExt": "psthing.com",         // "External Public DNS Name"
        ````
1. Open the following File and fill out all of the information ADF\tenants\HUB\AZC1-Global.json
    1. The file name should match your Primary Azure Region that you will deploy into
        ````
          "Global": {
            "HubRGName": "AZC1-BRW-HUB-RG-P0",          // "{Primary-Azure-Region-AZXX}-{appname-3-characters-max-upper-case}-RG-P0" P0 is a Hub
            "hubVnetName": "AZC1-BRW-HUB-P0-vn",        // "{Primary-Azure-Region-AZXX}-{appname-3-characters-max-upper-case}-P0-vn" P0 is a Hub
            "KVName": "AZC1-BRW-HUB-P0-kvVault01",      // "{Primary-Azure-Region-AZXX}-{orgname-3-char-max-upper-case}-{appname-3-characters-max-upper-case}-P0-kvVault01" P0 is a Hub
                                                    // max length of keyvault name is 24 chars
            "KVUrl": "https://AZC1-BRW-HUB-P0-kvVault01.vault.azure.net/",       // Given we haven't deployed this as yet, you will have to update the CertURL later.
            "certificateUrl": "https://azc1-brw-hub-p0-kvvault01.vault.azure.net:443/secrets/WildcardCert/e0066997eae945529c84fbf815f7759f",
            "networkId": ["10.0.",144],             // The is the /20 Network Address Space that will be divided up in this region
            "nsgRGName": "AZC1-BRW-HUB-RG-P0",          // "{Primary-Azure-Region-AZXX}-{appname-3-characters-max-upper-case}-RG-P0" P0 is a Hub
            "RTRGName": "AZC1-BRW-HUB-RG-P0",           // "{Primary-Azure-Region-AZXX}-{appname-3-characters-max-upper-case}-RG-P0" P0 is a Hub
            "RTName": "rtContoso-Hub",
            "dnsZoneRGName": "AZC1-BRW-HUB-RG-P0"      // "{Primary-Azure-Region-AZXX}-{appname-3-characters-max-upper-case}-RG-P0" P0 is a Hub
        ````
1. Open the following File and fill out all of the information ADF\tenants\HUB\AZE2-Global.json
    1. The file name should match your Secondary Azure Region that you will deploy into
    1. This will have a different network range etc, this is for DR
    1. Fill out the appropriate information, including the Keyvault and RG name references, since we will bootstrap those in both regions.
1. We are now ready to Deploy the initial Storage Account
    1. Make sure you are logged into Azure PowerShell
        1. First make sure you are in the correct Azure Tenant/Subscription
        1. More info is in this file: [ADF\1-PrereqsToDeploy\0-ConnectToAzureSelectSubscription.ps1]
    1. Although these helper scripts live in this directory [ADF\1-PrereqsToDeploy], we deploy them from a helper script from within your Tenant.
    1. Open up the Helper Script [ADF\tenants\HUB\azure-Deploy.ps1]
    1. In order to Load some settings into memory, once you open that file you press F5 to load it.
        1. You should see something similar to the following after you run F5
        ````powershell
        VERBOSE: ArtifactStagingDirectory is [D:\repos\AzureDeploymentFramework\ADF] and App is [HUB]
        ````
    1. Then after that you can create the intial Resource Group and Storage Account
    1. You will see the lines below, that you can execute (make sure you did F5 first! and are in your subscription)
        ````powershell
        # Pre-reqs
        # Create Global Storage Account
        . ADF:\1-PrereqsToDeploy\1-CreateStorageAccountGlobal.ps1 -APP $App
        ````
        1. You wil see an output similar to below once the RG and Storage are created.
        1. This storage account is used for uploading Assets (for IaaS/VM Deployments) that you may need, such as software installs and also used for your Template Deployments.
        ````powershell
        VERBOSE: Global RGName: AZC1-BRW-HUB-RG-G1
        
        ResourceGroupName : AZC1-BRW-HUB-RG-G1
        Location          : centralus
        ProvisioningState : Succeeded
        Tags              :
        ResourceId        : /subscriptions/1f0713fe-9b12-4c8f-ab0c-26aba7aaa3e5/resourceGroups/AZC1-BRW-HUB-RG-G1
        
        
        ResourceGroupName           : AZC1-BRW-HUB-RG-G1
        StorageAccountName          : azc1brwhubg1saglobal
        Id                          : /subscriptions/1f0713fe-9b12-4c8f-ab0c-26aba7aaa3e5/resourceGroups/AZC1-BRW-HUB-RG-G1/providers/Microsoft.Storage/storageAccounts/azc1brwhubg1saglobal
        Location                    : centralus
        Sku                         : Microsoft.Azure.Commands.Management.Storage.Models.PSSku
        Kind                        : StorageV2
        Encryption                  : Microsoft.Azure.Management.Storage.Models.Encryption
        AccessTier                  : Hot
        CreationTime                : 1/17/2021 8:51:11 PM
        ````
1. In order to use Friendly Names for our Role Assignments in your configurations we need to do a 1 time export of these from your Subscription.
    1. Working in the same file [ADF\tenants\HUB\azure-Deploy.ps1]
    1. Execute this following line
        ````powershell
        # Export all role defintions
        . ADF:\1-PrereqsToDeploy\4.1-getRoleDefinitionTable.ps1 -APP $App
        ````
    1. This process will actually update the JSON object in the following file [ADF\tenants\HUB\Global-Config.json]
        1. You can open that file and format it if you like and then save it.
        1. Once you format it you will see the Role Definition Friendly names and the associated GUIDs
            ````json
            "RolesGroupsLookup": {
                "Storage Blob Delegator": {
                    "Id": "db58b8e5-c6ad-4a2a-8342-4190687cbf4a",
                    "Description": "Allows for generation of a user delegation key which can be used to sign SAS tokens"
                },
                "Managed Application Contributor Role": {
                    "Id": "641177b8-a67a-45b9-a033-47bc880bb21e",
                    "Description": "Allows for creating managed application resources."
                },
                ...
            ````
        1. If you add custom Role definitions in the future, then you should re-run this command to re-export them over the top
1. Create your Service Principals (Scripts are provided for GitHub and Azure DevOps), this document assumes GitHub
    1. This will create 1 Principal per Resource Group, Per Application
    1. You can go ahead and create all of them ahead of time, if you like
    1. You can always come back add more or also re-run this, it will check if they exist
    1. Execute this following line/s (One for each region)
        ````powershell
        # Create Service principal for Env.
        . ADF:\1-PrereqsToDeploy\4-Start-CreateServicePrincipalGH.ps1 -APP $App -Prefix AZC1 -Environments P0,G0,G1,D2,S1
        . ADF:\1-PrereqsToDeploy\4-Start-CreateServicePrincipalGH.ps1 -APP $App -Prefix AZE2 -Environments P0,S1
        ````
        1. Sample Output, this does several things
            1. Create the Application/Service Principal in Azure ActiveDirectory
            1. Creates the Secret in GitHub, this is used for Deployments (GitHub Workflows/Actions)
            1. Updates the Global-Global.json file to do friendly name lookups for the ServicePrincipal to the objectid
            ````powershell
            Secret                : System.Security.SecureString
            ServicePrincipalNames : {55ec7612-2d3a-43b8-a5b7-4a53fd905655, http://AzureDeploymentFramework_AZC1-BRW-HUB-RG-P0}
            ApplicationId         : 55ec7612-2d3a-43b8-a5b7-4a53fd905655
            ObjectType            : ServicePrincipal
            DisplayName           : AzureDeploymentFramework_AZC1-BRW-HUB-RG-P0
            Id                    : 9b537c42-3cfc-423b-955d-a83dbbfa0ac3
            Type                  :
            
            WARNING: Assigning role 'Reader' over scope '/subscriptions/1f0713fe-9b12-4c8f-ab0c-26aba7aaa3e5' to the new service principal.
    
            {"clientId":"55ec7612-2d3a-43b8-a5b7-4a53fd905655","clientSecret":"6b72ed30-80e9-4ca5-8178-5b4755f84b27","tenantId":"3254f91d-4657-40df-962d-c8e6dad75963","subscriptionId":"1f0713fe-9b12-4c8f-ab0c-26aba7aaa3e5","activeDirectoryEndpointUrl":"https://login.microsoftonline.com","resourceManagerEndpointUrl":"https://management.azure.com/","activeDirectoryGraphResourceId":"https://graph.windows.net/","sqlManagementEndpointUrl":"https://management.core.windows.net:8443/","galleryEndpointUrl":"https://gallery.azure.com/","managementEndpointUrl":"https://management.core.windows.net/"}
            
            ✓ Set secret AZC1_HUB_RG_P0 for brwilkinson/AzureDeploymentFramework
            
            VERBOSE: Adding Service Principal [AzureDeploymentFramework_AZC1-BRW-HUB-RG-P0] to Global-Global.json
            
            AzureDeploymentFramework_AZC1-BRW-HUB-RG-P0 : 9b537c42-3cfc-423b-955d-a83dbbfa0ac3
            AzureDeploymentFramework_AZC1-BRW-HUB-RG-G0 : c4acb09d-7fe0-4e50-8988-b11b67711841
            AzureDeploymentFramework_AZC1-BRW-HUB-RG-G1 : a744f350-9757-4943-b42e-f96e88b42f96
            AzureDeploymentFramework_AZC1-BRW-HUB-RG-D2 : 8c1101e5-d23e-4f15-bb4d-9b2156898d8f
            AzureDeploymentFramework_AZC1-BRW-HUB-RG-S1 : 1509358e-331b-44d3-83e1-3a880832328f
            ````

1. BootStrap the Hub Resource Group Creation and also the Keyvaults in the Primary and Secondary Region
    1. Although these helper scripts live in this directory [ADF\1-PrereqsToDeploy], we deploy them from a helper script from within your Tenant.
    1. Open up the Helper Script [ADF\tenants\HUB\azure-Deploy.ps1]
    1. Then execute the following
        ````powershell
        # Bootstrap Hub RGs and Keyvaults
        . ADF:\1-PrereqsToDeploy\1-CreateHUBKeyVaults.ps1 -APP $App
        ````
    1. You should see the following output
        ````powershell
        VERBOSE: Primary HUB RGName: AZC1-BRW-HUB-RG-P0
        VERBOSE: Primary KV Name: AZC1-BRW-HUB-P0-kvVLT01
        VERBOSE: Secondary HUB RGName: AZE2-BRW-HUB-RG-P0
        VERBOSE: Secondary KV Name: AZE2-BRW-HUB-P0-kvVLT01
        ````
    1. Following this you can manually create the following 2 Secrets
        1. localadmin, then provide the local admin password for your Virtual Machines

1. In order to deploy from these Service Principals, they need to be delegated access over certain scopes in Azure
    1. These Role Assignments are handled within the Deployment Scripts, however there is a chicken or egg problem
    1. I would recommend 2 Manual Role assignements to get things started
        1. Assign the [GO] Principal E.g. "AzureDeploymentFramework_AZC1-BRW-HUB-RG-G0" as Owner on the Subscription.
            1. This is the principal that executes all role assignments and also creates RG's.
            1. As a reminder, G0 stands for Subscription Level.
            1. This principal will do the following:
                1. Upload files to the storage account, so inherits access via owner to the storage account keys
                1. Deploy a Template by reading from the Keyvault (1 in each regional hub)
                1. Then it will run the intial template deployment to Create RG's and perform RBAC Assignments on those RG's
        1. Assign the [G0] Principal E.g. E.g. "AzureDeploymentFramework_AZC1-BRW-HUB-RG-G0" as "Key Vault Secrets User (preview)"
            1. You will want to do this on both Hubs i.e. both P0 Resource Groups.
        1. While you are setting this up, you should also assign the below RBAC Role Assignments on your own account
            1. "Owner" on Subscription
            1. "Key Vault Secrets Officer (preview)" on the Hub RG's i.e. P0
                1. We will need to create 2 secrets in order to deploy in the next step, so this will enable you to create these
            1. You can easily remove these later, once the Workflows have all been setup.

1. Go into the Keyvault in your primary Hub.
    1. Create 2 Secrets (These are the default securestring parameters on all templates, you can add more later)
        1. *localadmin* (choose your domain or local admin password here)
        1. *sshPublic* (any value here, Update this later), consider moving, now this is on GitHub, not azureDevops

1. In order to deploy WebSites, you should create some Web Certs, you can also do this from a Public Provider, however we will use self signed here.
    1. Although these helper scripts live in this directory [ADF\1-PrereqsToDeploy], we deploy them from a helper script from within your Tenant.
    1. Open up the Helper Script [ADF\tenants\HUB\azure-Deploy.ps1]
    1. Then execute the following
        ````powershell
        # Create Global Web Create
        . ADF:\1-PrereqsToDeploy\2-CreateUploadWebCertAdminCreds.ps1 -APP $App
        ````
    1. The cert will be created using the password from your keyvault localadmin secret that you set earlier
    1. The DNS names used on the cert are from the Global-Global.json [CertURLs] property.
    1. This certificate will be deploy to all VM's in the Root/Trusted/My root stores
    1. When you execute the above script it will also update the [CertificateThumbprint] value in the Global-Global.json file
    1. When you deploy websites, this cert will be bound to SSL sites in IIS.

1. Once you have Created the Secrets in the Primary Regional Hub Keyvault, you can sync the secrets to the Secondary Regional Hub Keyvault
    1. Although these helper scripts live in this directory [ADF\1-PrereqsToDeploy], we deploy them from a helper script from within your Tenant.
    1. Open up the Helper Script [ADF\tenants\HUB\azure-Deploy.ps1]
    1. Then execute the following
        ````powershell
        # Sync the keyvault from CentralUS to EastUS2 (Primary Region to Secondary Region)
        . ADF:\1-PrereqsToDeploy\3-Start-AzureKVSync.ps1
        ````
    1. The Primary and Secondary KV Name and Region Etc. comes from the Global meta data file that you updated earlier.
        1. i.e. [ADF\tenants\HUB\Global-Global.json]