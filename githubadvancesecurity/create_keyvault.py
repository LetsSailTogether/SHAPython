from azure.identity import AzureCliCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.keyvault.secrets import SecretClient
from azure.mgmt.keyvault.models import (
    VaultCreateOrUpdateParameters,
    VaultProperties,
    Sku,
    SkuName,
    AccessPolicyEntry,
    Permissions,
)
import os
from dotenv import load_dotenv

def create_key_vault(
    subscription_id: str,
    resource_group_name: str,
    vault_name: str,
    location: str = "eastus"
) -> str:
    """
    Create an Azure Key Vault and return its URL
    """
    # Initialize the credential
    credential = AzureCliCredential()
    
    # Initialize clients
    resource_client = ResourceManagementClient(credential, subscription_id)
    kv_client = KeyVaultManagementClient(credential, subscription_id)
    
    # Ensure resource group exists
    resource_client.resource_groups.create_or_update(
        resource_group_name,
        {"location": location}
    )
    
    # Get the current user's information from Azure CLI
    from subprocess import check_output
    import json
    
    # Get account information using Azure CLI
    try:
        from subprocess import check_output, PIPE, CalledProcessError
        import sys
        
        # Determine the correct path to az executable
        az_cmd = 'az.cmd' if sys.platform == 'win32' else 'az'
        
        # Get tenant ID
        account_info = json.loads(check_output([az_cmd, 'account', 'show'], 
                                             shell=True, 
                                             stderr=PIPE, 
                                             encoding='utf-8'))
        tenant_id = account_info['tenantId']
        
        # Get the current user's object ID
        user_info = json.loads(check_output([az_cmd, 'ad', 'signed-in-user', 'show'], 
                                          shell=True, 
                                          stderr=PIPE, 
                                          encoding='utf-8'))
        object_id = user_info['id']
    except CalledProcessError as e:
        print(f"Error executing Azure CLI command: {e.output.decode() if e.output else str(e)}")
        print("Please ensure you are logged in to Azure CLI using 'az login'")
        raise
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        raise
    
    # Create vault parameters
    parameters = VaultCreateOrUpdateParameters(
        location=location,
        properties=VaultProperties(
            tenant_id=tenant_id,
            sku=Sku(name=SkuName.standard.value),
            access_policies=[
                AccessPolicyEntry(
                    tenant_id=tenant_id,
                    object_id=object_id,
                    permissions=Permissions(
                        secrets=["all"],
                        certificates=["all"],
                        keys=["all"]
                    )
                )
            ],
            enable_rbac_authorization=False,
            enable_soft_delete=True,
            soft_delete_retention_in_days=7,
            enable_purge_protection=True
        )
    )
    
    # Create the Key Vault
    vault = kv_client.vaults.begin_create_or_update(
        resource_group_name,
        vault_name,
        parameters
    ).result()
    
    vault_url = f"https://{vault_name}.vault.azure.net/"
    return vault_url

def store_initial_secrets(vault_url: str, secrets: dict):
    """
    Store initial secrets in the Key Vault
    """
    credential = AzureCliCredential()
    secret_client = SecretClient(vault_url=vault_url, credential=credential)
    
    for secret_name, secret_value in secrets.items():
        secret_client.set_secret(secret_name, secret_value)
        print(f"Secret '{secret_name}' has been stored in Key Vault")

def main():
    # Load environment variables
    load_dotenv()
    
    # Configuration
    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
    if not subscription_id:
        raise ValueError("Please set AZURE_SUBSCRIPTION_ID environment variable")
    
    resource_group = "github-security-rg"
    vault_name = "github-security-kv"
    location = "eastus"
    
    try:
        # Create Key Vault
        print(f"Creating Key Vault '{vault_name}'...")
        vault_url = create_key_vault(subscription_id, resource_group, vault_name, location)
        print(f"Key Vault created successfully: {vault_url}")
        
        # Store initial secrets
        secrets = {
            "github-token": os.getenv("GITHUB_TOKEN", ""),
            "email-user": os.getenv("EMAIL_USER", ""),
            "email-password": os.getenv("EMAIL_PASSWORD", "")
        }
        
        if any(secrets.values()):
            print("\nStoring initial secrets...")
            store_initial_secrets(vault_url, {k: v for k, v in secrets.items() if v})
        
        # Update .env file with the Key Vault URL
        env_path = os.path.join(os.path.dirname(__file__), '.env')
        env_content = f"\nAZURE_KEYVAULT_URL={vault_url}"
        
        # Append or create .env file
        mode = 'a' if os.path.exists(env_path) else 'w'
        with open(env_path, mode) as f:
            f.write(env_content)
            
        print("\nKey Vault setup complete!")
        print(f"Added AZURE_KEYVAULT_URL to .env file")
        print(f"Key Vault URL: {vault_url}")
        
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()