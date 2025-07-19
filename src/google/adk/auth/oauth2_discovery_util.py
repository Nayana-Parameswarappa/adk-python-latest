# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""OAuth2 discovery utilities for automatic configuration discovery."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

import httpx
from fastapi.openapi.models import OAuth2
from fastapi.openapi.models import OAuthFlowClientCredentials
from fastapi.openapi.models import OAuthFlows
from google.adk.utils.feature_decorator import experimental

logger = logging.getLogger(__name__)

# OAuth Discovery Constants
OAUTH_PROTECTED_RESOURCE_DISCOVERY = ".well-known/oauth-protected-resource"
OAUTH_AUTHORIZATION_SERVER_DISCOVERY = ".well-known/oauth-authorization-server"


@experimental
async def discover_oauth_configuration(
    base_url: str,
    timeout: float = 10.0
) -> Optional[Dict[str, Any]]:
  """
  Discover OAuth2 authorization server configuration for a given base URL.
  
  This function implements OAuth 2.0 Authorization Server Metadata discovery
  according to RFC 8414. It tries multiple discovery endpoints in order:
  
  1. .well-known/oauth-protected-resource (for resource servers)
  2. .well-known/oauth-authorization-server (for auth servers)
  
  Args:
      base_url: The base URL of the server to discover OAuth config for
      timeout: Request timeout in seconds
      
  Returns:
      Dictionary containing discovered OAuth configuration, or None if discovery fails
  """
  base_url = base_url.rstrip('/')
  
  discovery_endpoints = [
    OAUTH_PROTECTED_RESOURCE_DISCOVERY,
    OAUTH_AUTHORIZATION_SERVER_DISCOVERY
  ]
  
  async with httpx.AsyncClient(timeout=timeout) as client:
    for endpoint in discovery_endpoints:
      discovery_url = f"{base_url}/{endpoint}"
      try:
        logger.debug(f"Attempting OAuth discovery at: {discovery_url}")
        
        response = await client.get(discovery_url)
        response.raise_for_status()
        
        config = response.json()
        logger.info(f"Successfully discovered OAuth configuration at {discovery_url}")
        
        # Validate required fields exist
        if _validate_oauth_discovery_response(config):
          return config
        else:
          logger.warning(f"Invalid OAuth discovery response from {discovery_url}")
          
      except httpx.HTTPStatusError as e:
        logger.debug(f"OAuth discovery failed at {discovery_url}: HTTP {e.response.status_code}")
      except (httpx.RequestError, json.JSONDecodeError) as e:
        logger.debug(f"OAuth discovery failed at {discovery_url}: {e}")
      except Exception as e:
        logger.warning(f"Unexpected error during OAuth discovery at {discovery_url}: {e}")
  
  logger.info(f"OAuth discovery failed for {base_url} - no valid configuration found")
  return None


@experimental
def _validate_oauth_discovery_response(config: Dict[str, Any]) -> bool:
  """
  Validate OAuth discovery response contains required fields.
  
  Args:
      config: The discovered OAuth configuration
      
  Returns:
      True if configuration is valid, False otherwise
  """
  # For oauth-protected-resource discovery
  if "authorization_servers" in config:
    return isinstance(config["authorization_servers"], list) and bool(config["authorization_servers"])
  
  # For oauth-authorization-server discovery  
  if "token_endpoint" in config:
    return isinstance(config["token_endpoint"], str) and bool(config["token_endpoint"])
    
  return False


@experimental
async def create_oauth_scheme_from_discovery(
    base_url: str,
    scopes: Optional[list[str]] = None,
    timeout: float = 10.0
) -> Optional[OAuth2]:
  """
  Create an OAuth2 auth scheme by automatically discovering OAuth configuration.
  
  Args:
      base_url: The base URL to discover OAuth configuration for
      scopes: List of OAuth scopes to request
      timeout: Discovery request timeout in seconds
      
  Returns:
      OAuth2 auth scheme with discovered configuration, or None if discovery fails
  """
  config = await discover_oauth_configuration(base_url, timeout)
  if not config:
    return None
    
  # Extract token endpoint from discovery response
  token_endpoint = None
  
  if "authorization_servers" in config:
    # oauth-protected-resource response - get first auth server
    auth_servers = config["authorization_servers"]
    if auth_servers:
      auth_server_url = auth_servers[0]
      # Try to discover the actual auth server config
      auth_server_config = await discover_oauth_configuration(auth_server_url, timeout)
      if auth_server_config and "token_endpoint" in auth_server_config:
        token_endpoint = auth_server_config["token_endpoint"]
      else:
        # Fallback: assume standard /token endpoint
        token_endpoint = f"{auth_server_url.rstrip('/')}/token"
        
  elif "token_endpoint" in config:
    # oauth-authorization-server response
    token_endpoint = config["token_endpoint"]
  
  if not token_endpoint:
    logger.warning("Could not determine token endpoint from OAuth discovery")
    return None
    
  # Create scopes dictionary
  scopes = scopes or ["read", "write"]
  scopes_dict = {scope: f"Access to {scope}" for scope in scopes}
  
  # Create OAuth2 scheme with client credentials flow
  return OAuth2(
    flows=OAuthFlows(
      clientCredentials=OAuthFlowClientCredentials(
        tokenUrl=token_endpoint,
        scopes=scopes_dict
      )
    )
  ) 