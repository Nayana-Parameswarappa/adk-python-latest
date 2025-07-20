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

"""OAuth discovery configuration for MCP tools."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class MCPAuthDiscovery:
    """Configuration for OAuth2 discovery in MCP tools.
    
    This class encapsulates parameters needed for automatic OAuth2 discovery,
    providing a clean API for configuring how MCPToolset should discover 
    OAuth2 token endpoints.
    
    Attributes:
        base_url: The base server URL for OAuth discovery endpoints (e.g., "http://server:9204").
            OAuth .well-known endpoints will be queried at this URL root.
        timeout: Timeout in seconds for OAuth discovery requests (default: 10.0).
        enabled: Whether OAuth discovery is enabled (default: True).
        
    Note:
        OAuth scopes should be specified in the auth_scheme parameter of MCPToolset,
        not in this discovery configuration. Discovery only finds token endpoints.
            
    Example:
        >>> # Scopes go in auth scheme, not discovery config
        >>> auth_scheme = OAuth2(
        ...     flows=OAuthFlows(
        ...         clientCredentials=OAuthFlowClientCredentials(
        ...             tokenUrl="",  # Will be discovered
        ...             scopes={"read": "Read access", "write": "Write access"}
        ...         )
        ...     )
        ... )
        >>> discovery = MCPAuthDiscovery(
        ...     base_url="http://localhost:9204",
        ...     timeout=15.0
        ... )
        >>> toolset = MCPToolset(
        ...     connection_params=StreamableHTTPConnectionParams(url="http://localhost:9204/mcp/"),
        ...     auth_scheme=auth_scheme,
        ...     auth_credential=credential,
        ...     auth_discovery=discovery
        ... )
    """
    
    base_url: str
    timeout: float = 10.0
    enabled: bool = True
    
    def __post_init__(self):
        """Validate and normalize configuration after initialization."""
        # Normalize base URL - remove trailing slash
        if self.base_url:
            self.base_url = self.base_url.rstrip('/')
            
        # Validate timeout
        if self.timeout <= 0:
            raise ValueError("Discovery timeout must be positive")
            
        # Validate base URL
        if not self.base_url or not self.base_url.strip():
            raise ValueError("Discovery base_url is required and cannot be empty")
    
    @property
    def is_enabled(self) -> bool:
        """Check if OAuth discovery is enabled and properly configured."""
        return self.enabled and bool(self.base_url) 
