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

"""OAuth2 credential exchanger implementation."""

from __future__ import annotations

import logging
from typing import Optional

from fastapi.openapi.models import OAuth2
from google.adk.auth.auth_credential import AuthCredential
from google.adk.auth.auth_schemes import AuthScheme
from google.adk.auth.auth_schemes import OAuthGrantType
from google.adk.auth.oauth2_credential_util import create_oauth2_session
from google.adk.auth.oauth2_credential_util import update_credential_with_tokens
from google.adk.utils.feature_decorator import experimental
from typing_extensions import override

from .base_credential_exchanger import BaseCredentialExchanger
from .base_credential_exchanger import CredentialExchangError

try:
  from authlib.integrations.requests_client import OAuth2Session

  AUTHLIB_AVAILABLE = True
except ImportError:
  AUTHLIB_AVAILABLE = False

logger = logging.getLogger("google_adk." + __name__)


@experimental
class OAuth2CredentialExchanger(BaseCredentialExchanger):
  """Exchanges OAuth2 credentials from authorization responses or client credentials."""

  @override
  async def exchange(
      self,
      auth_credential: AuthCredential,
      auth_scheme: Optional[AuthScheme] = None,
  ) -> AuthCredential:
    """Exchange OAuth2 credential based on the flow type.
    if credential exchange failed, the original credential will be returned.

    Args:
        auth_credential: The OAuth2 credential to exchange.
        auth_scheme: The OAuth2 authentication scheme.

    Returns:
        The exchanged credential with access token.

    Raises:
        CredentialExchangError: If auth_scheme is missing.
    """
    if not auth_scheme:
      raise CredentialExchangError(
          "auth_scheme is required for OAuth2 credential exchange"
      )

    if not AUTHLIB_AVAILABLE:
      # If authlib is not available, we cannot exchange the credential.
      # We return the original credential without exchange.
      # The client using this tool can decide to exchange the credential
      # themselves using other lib.
      logger.warning(
          "authlib is not available, skipping OAuth2 credential exchange."
      )
      return auth_credential

    if auth_credential.oauth2 and auth_credential.oauth2.access_token:
      return auth_credential

    # Determine the OAuth2 flow type
    grant_type = self._get_grant_type(auth_scheme)
    
    if grant_type == OAuthGrantType.CLIENT_CREDENTIALS:
      return await self._exchange_client_credentials(auth_credential, auth_scheme)
    elif grant_type == OAuthGrantType.AUTHORIZATION_CODE:
      return await self._exchange_authorization_code(auth_credential, auth_scheme)
    else:
      logger.warning(f"Unsupported OAuth2 grant type: {grant_type}")
      return auth_credential

  def _get_grant_type(self, auth_scheme: AuthScheme) -> Optional[OAuthGrantType]:
    """Determine the OAuth2 grant type from the auth scheme."""
    if isinstance(auth_scheme, OAuth2) and auth_scheme.flows:
      return OAuthGrantType.from_flow(auth_scheme.flows)
    return None

  async def _exchange_client_credentials(
      self, 
      auth_credential: AuthCredential, 
      auth_scheme: AuthScheme
  ) -> AuthCredential:
    """Handle OAuth2 client credentials flow."""
    
    if not isinstance(auth_scheme, OAuth2) or not auth_scheme.flows.clientCredentials:
      logger.warning("No client credentials flow configuration found")
      return auth_credential
        
    flow = auth_scheme.flows.clientCredentials
    token_url = flow.tokenUrl
    scopes = list(flow.scopes.keys()) if flow.scopes else []
    
    if not auth_credential.oauth2 or not auth_credential.oauth2.client_id or not auth_credential.oauth2.client_secret:
      logger.error("Client ID and secret required for client credentials flow")
      return auth_credential
    
    try:
      # Create OAuth2 session for client credentials
      client = OAuth2Session(
          auth_credential.oauth2.client_id,
          auth_credential.oauth2.client_secret,
          scope=" ".join(scopes),
      )
      
      # Fetch token using client credentials grant
      tokens = client.fetch_token(
          token_url,
          grant_type=OAuthGrantType.CLIENT_CREDENTIALS,
      )
      
      # Update credential with tokens
      update_credential_with_tokens(auth_credential, tokens)
      logger.debug("Successfully exchanged OAuth2 client credentials")
      
    except Exception as e:
      logger.error("Failed to exchange OAuth2 client credentials: %s", e)
      return auth_credential

    return auth_credential

  async def _exchange_authorization_code(
      self, 
      auth_credential: AuthCredential, 
      auth_scheme: AuthScheme
  ) -> AuthCredential:
    """Handle OAuth2 authorization code flow (existing logic)."""
    
    client, token_endpoint = create_oauth2_session(auth_scheme, auth_credential)
    if not client:
      logger.warning("Could not create OAuth2 session for token exchange")
      return auth_credential

    try:
      tokens = client.fetch_token(
          token_endpoint,
          authorization_response=auth_credential.oauth2.auth_response_uri if auth_credential.oauth2 else None,
          code=auth_credential.oauth2.auth_code if auth_credential.oauth2 else None,
          grant_type=OAuthGrantType.AUTHORIZATION_CODE,
      )
      update_credential_with_tokens(auth_credential, tokens)
      logger.debug("Successfully exchanged OAuth2 authorization code")
    except Exception as e:
      # TODO reconsider whether we should raise errors in this case
      logger.error("Failed to exchange OAuth2 authorization code: %s", e)
      # Return original credential on failure
      return auth_credential

    return auth_credential
