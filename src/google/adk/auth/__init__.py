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

"""Auth configurations for Google ADK."""

from .auth_credential import AuthCredential
from .auth_credential import AuthCredentialTypes
from .auth_credential import OAuth2Auth
from .auth_credential import ServiceAccount
from .auth_handler import AuthHandler
from .auth_preprocessor import AuthPreprocessor
from .auth_schemes import AuthScheme
from .auth_schemes import OAuthGrantType
from .auth_schemes import OpenIdConnectWithConfig
from .auth_tool import AuthTool
from .auth_tool import AuthToolArguments
from .credential_manager import CredentialManager
from .oauth2_discovery_util import discover_oauth_configuration
from .oauth2_discovery_util import create_oauth_scheme_from_discovery

__all__ = [
    "AuthCredential",
    "AuthCredentialTypes",
    "AuthHandler",
    "AuthPreprocessor",
    "AuthScheme",
    "AuthTool",
    "AuthToolArguments",
    "CredentialManager",
    "OAuthGrantType",
    "OAuth2Auth",
    "OpenIdConnectWithConfig",
    "ServiceAccount",
    "discover_oauth_configuration",
    "create_oauth_scheme_from_discovery",
]
